import csv
import difflib
import io
import os
import sqlite3
from pathlib import Path
from datetime import datetime
from functools import wraps

import pandas as pd
from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IS_VERCEL = os.getenv("VERCEL") == "1"
DATA_DIR = os.getenv("APP_DATA_DIR", "/tmp" if IS_VERCEL else BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, "audit.db")
SEED_SQL_PATH = os.path.join(BASE_DIR, "seed_data.sql")
DEFAULT_ADMIN_NAME = "admin"
DEFAULT_ADMIN_PHONE = "9111080628"
DEFAULT_ADMIN_PASSWORD = "1234"
ALL_OUTLETS_VALUE = "ALL"

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["DB_INITIALIZED"] = False


# ---------------------------
# Database helpers
# ---------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS outlets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS outlet_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias TEXT UNIQUE NOT NULL,
            outlet_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(outlet_name) REFERENCES outlets(name)
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'outlet_head', 'sub_auditor')),
            outlet TEXT,
            created_by_admin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            tag_outlet TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'ended')),
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            barcode TEXT NOT NULL,
            expected_qty INTEGER NOT NULL,
            department TEXT NOT NULL,
            article_name TEXT NOT NULL,
            outlet TEXT NOT NULL,
            UNIQUE(audit_id, barcode, department),
            FOREIGN KEY(audit_id) REFERENCES audits(id)
        );

        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            outlet TEXT NOT NULL DEFAULT '',
            department TEXT NOT NULL,
            sub_auditor_id INTEGER NOT NULL,
            assigned_by INTEGER NOT NULL,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            frozen_at TEXT,
            UNIQUE(audit_id, outlet, department),
            FOREIGN KEY(audit_id) REFERENCES audits(id),
            FOREIGN KEY(sub_auditor_id) REFERENCES users(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            barcode TEXT NOT NULL,
            outlet TEXT NOT NULL DEFAULT '',
            department TEXT NOT NULL,
            scanned_qty INTEGER NOT NULL,
            scanned_by INTEGER NOT NULL,
            manual_entry INTEGER NOT NULL DEFAULT 0,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY(audit_id) REFERENCES audits(id),
            FOREIGN KEY(scanned_by) REFERENCES users(id)
        );
        """
    )
    migrate_assignments_table(db)
    migrate_scans_table(db)
    bootstrap_seed_data_if_empty(db)

    # Backfill outlets from existing data for smooth upgrades.
    db.execute(
        """
        INSERT OR IGNORE INTO outlets (name, created_at)
        SELECT DISTINCT TRIM(outlet), ?
        FROM users
        WHERE outlet IS NOT NULL AND TRIM(outlet) <> ''
        """,
        (now_ts(),),
    )
    db.execute(
        """
        INSERT OR IGNORE INTO outlets (name, created_at)
        SELECT DISTINCT TRIM(tag_outlet), ?
        FROM audits
        WHERE tag_outlet IS NOT NULL AND TRIM(tag_outlet) <> '' AND TRIM(tag_outlet) <> ?
        """,
        (now_ts(), ALL_OUTLETS_VALUE),
    )
    db.execute(
        """
        INSERT OR IGNORE INTO outlet_aliases (alias, outlet_name, created_at)
        SELECT name, name, ?
        FROM outlets
        """,
        (now_ts(),),
    )

    # Seed one admin if no admin exists.
    admin = db.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    if not admin:
        # Phone is globally unique in users table.
        db.execute(
            """
            INSERT INTO users (name, phone, password_hash, role, outlet, created_by_admin, created_at)
            VALUES (?, ?, ?, 'admin', '', 1, ?)
            """,
            (
                DEFAULT_ADMIN_NAME,
                DEFAULT_ADMIN_PHONE,
                generate_password_hash(DEFAULT_ADMIN_PASSWORD),
                now_ts(),
            ),
        )
    db.commit()


def bootstrap_seed_data_if_empty(db):
    if not os.path.exists(SEED_SQL_PATH):
        return
    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row and row["c"] > 0:
        return
    with open(SEED_SQL_PATH, "r", encoding="utf-8") as f:
        sql = f.read().strip()
    if sql:
        db.executescript(sql)


def migrate_assignments_table(db):
    cols = db.execute("PRAGMA table_info(assignments)").fetchall()
    col_names = {c["name"] for c in cols}
    if "outlet" in col_names:
        return

    db.executescript(
        """
        ALTER TABLE assignments RENAME TO assignments_old;

        CREATE TABLE assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            outlet TEXT NOT NULL DEFAULT '',
            department TEXT NOT NULL,
            sub_auditor_id INTEGER NOT NULL,
            assigned_by INTEGER NOT NULL,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            frozen_at TEXT,
            UNIQUE(audit_id, outlet, department),
            FOREIGN KEY(audit_id) REFERENCES audits(id),
            FOREIGN KEY(sub_auditor_id) REFERENCES users(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id)
        );
        """
    )
    db.execute(
        """
        INSERT OR IGNORE INTO assignments (
            id, audit_id, outlet, department, sub_auditor_id, assigned_by, is_frozen, frozen_at
        )
        SELECT
            ao.id,
            ao.audit_id,
            COALESCE(NULLIF(a.tag_outlet, ?), COALESCE(u.outlet, '')),
            ao.department,
            ao.sub_auditor_id,
            ao.assigned_by,
            ao.is_frozen,
            ao.frozen_at
        FROM assignments_old ao
        LEFT JOIN audits a ON a.id = ao.audit_id
        LEFT JOIN users u ON u.id = ao.sub_auditor_id
        """,
        (ALL_OUTLETS_VALUE,),
    )
    db.execute("DROP TABLE assignments_old")


def migrate_scans_table(db):
    cols = db.execute("PRAGMA table_info(scans)").fetchall()
    col_names = {c["name"] for c in cols}
    if "outlet" in col_names:
        return

    db.execute("ALTER TABLE scans ADD COLUMN outlet TEXT NOT NULL DEFAULT ''")
    db.execute(
        """
        UPDATE scans
        SET outlet = COALESCE(
            (SELECT CASE WHEN a.tag_outlet = ? THEN '' ELSE a.tag_outlet END FROM audits a WHERE a.id = scans.audit_id),
            ''
        )
        """,
        (ALL_OUTLETS_VALUE,),
    )


@app.before_request
def ensure_db_initialized():
    if not app.config["DB_INITIALIZED"]:
        init_db()
        app.config["DB_INITIALIZED"] = True


# ---------------------------
# Auth and role helpers
# ---------------------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in allowed_roles:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)

        return wrapper

    return decorator


def normalize_key(value):
    raw = str(value).strip().lower().replace("_", " ")
    return "".join(ch for ch in raw if ch.isalnum() or ch.isspace()).strip()


def canonical_column_name(name):
    key = normalize_key(name)
    mapping = {
        "barcode": "barcode",
        "bar code": "barcode",
        "item code": "barcode",
        "itemcode": "barcode",
        "qty": "qty",
        "quantity": "qty",
        "qnty": "qty",
        "department": "department",
        "deparment": "department",
        "departmer": "department",
        "dept": "department",
        "article name": "article name",
        "articlename": "article name",
        "article": "article name",
        "item name": "article name",
        "product name": "article name",
        "outlet": "outlet",
        "store": "outlet",
        "location": "outlet",
        "branch": "outlet",
    }
    return mapping.get(key)


def get_outlet_names():
    rows = get_db().execute("SELECT name FROM outlets ORDER BY name").fetchall()
    return [r["name"] for r in rows]


def outlet_lookup():
    lookup = {}
    for outlet in get_outlet_names():
        lookup[normalize_key(outlet)] = outlet
    rows = get_db().execute("SELECT alias, outlet_name FROM outlet_aliases").fetchall()
    for row in rows:
        lookup[normalize_key(row["alias"])] = row["outlet_name"]
    return lookup


def resolve_outlet_name(raw_outlet, lookup):
    key = normalize_key(raw_outlet)
    return lookup.get(key)


def best_similar_outlet(raw_outlet, outlet_names):
    source = normalize_key(raw_outlet).replace(" ", "")
    if not source:
        return None
    best_name = None
    best_score = 0.0
    for outlet in outlet_names:
        target = normalize_key(outlet).replace(" ", "")
        if not target:
            continue
        score = difflib.SequenceMatcher(None, source, target).ratio()
        if score > best_score:
            best_score = score
            best_name = outlet
    if best_name and best_score >= 0.86:
        return best_name
    return None


def ensure_outlet_from_source(raw_outlet, db, lookup, outlet_names):
    canonical = resolve_outlet_name(raw_outlet, lookup)
    if canonical:
        return canonical, None

    similar = best_similar_outlet(raw_outlet, outlet_names)
    if similar:
        db.execute(
            """
            INSERT OR IGNORE INTO outlet_aliases (alias, outlet_name, created_at)
            VALUES (?, ?, ?)
            """,
            (raw_outlet, similar, now_ts()),
        )
        lookup[normalize_key(raw_outlet)] = similar
        return similar, ("alias", raw_outlet, similar)

    db.execute(
        """
        INSERT OR IGNORE INTO outlets (name, created_at)
        VALUES (?, ?)
        """,
        (raw_outlet, now_ts()),
    )
    db.execute(
        """
        INSERT OR IGNORE INTO outlet_aliases (alias, outlet_name, created_at)
        VALUES (?, ?, ?)
        """,
        (raw_outlet, raw_outlet, now_ts()),
    )
    if raw_outlet not in outlet_names:
        outlet_names.append(raw_outlet)
    lookup[normalize_key(raw_outlet)] = raw_outlet
    return raw_outlet, ("created", raw_outlet, raw_outlet)


def decode_upload_bytes(raw_bytes):
    encodings = ["utf-8-sig", "utf-16", "cp1252", "latin-1"]
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    raise ValueError(
        "Could not decode file. Save CSV as UTF-8 (or use Excel format .xlsx) and upload again."
    )


def load_upload_dataframe(file_storage, ext):
    if ext == ".csv":
        raw_bytes = file_storage.read()
        # Some users upload xlsx with .csv extension; detect ZIP signature.
        if raw_bytes.startswith(b"PK\x03\x04"):
            try:
                return pd.read_excel(io.BytesIO(raw_bytes), header=None, dtype=str)
            except Exception as ex:
                raise ValueError(f"Could not parse uploaded file as Excel: {ex}") from ex

        raw = decode_upload_bytes(raw_bytes)
        try:
            return pd.read_csv(
                io.StringIO(raw),
                sep=None,
                engine="python",
                header=None,
                dtype=str,
                on_bad_lines="skip",
            )
        except Exception as ex:
            candidates = [",", ";", "\t", "|"]
            best_df = None
            best_cols = 0
            for sep in candidates:
                try:
                    df = pd.read_csv(
                        io.StringIO(raw),
                        sep=sep,
                        header=None,
                        dtype=str,
                        on_bad_lines="skip",
                    )
                    cols = int(df.shape[1]) if not df.empty else 0
                    if cols > best_cols:
                        best_cols = cols
                        best_df = df
                except Exception:
                    continue
            if best_df is not None and best_cols > 1:
                return best_df
            # Last resort: split rows by repeated spaces (fixed-width-like exports).
            try:
                lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
                parsed = []
                for ln in lines:
                    parts = [p.strip() for p in ln.split("  ") if p.strip()]
                    if len(parts) <= 1:
                        parts = [p.strip() for p in ln.split("\t") if p.strip()]
                    parsed.append(parts)
                max_cols = max((len(r) for r in parsed), default=0)
                if max_cols > 1:
                    normalized = [r + [""] * (max_cols - len(r)) for r in parsed]
                    return pd.DataFrame(normalized)
            except Exception:
                pass
            raise ValueError(
                "Could not parse CSV delimiter. Save as comma-separated CSV or upload .xlsx."
            ) from ex
    try:
        return pd.read_excel(file_storage, header=None, dtype=str)
    except Exception as ex:
        raise ValueError(f"Could not parse Excel file: {ex}") from ex


def detect_header_row(frame, required):
    best_idx = None
    best_score = -1
    best_labels = []
    max_scan = min(10, len(frame.index))
    for i in range(max_scan):
        values = frame.iloc[i].tolist()
        labels = [canonical_column_name(v) for v in values]
        found = {l for l in labels if l}
        score = len(found & required)
        if score > best_score:
            best_score = score
            best_idx = i
            best_labels = labels
    return best_idx, best_labels, best_score


def parse_uploaded_items(file_storage):
    required = {"barcode", "qty", "department", "article name", "outlet"}
    ext = Path(file_storage.filename or "").suffix.lower()

    if ext not in {".csv", ".xls", ".xlsx"}:
        raise ValueError("Upload must be CSV or Excel (.csv, .xls, .xlsx).")

    frame = load_upload_dataframe(file_storage, ext)
    if frame.empty:
        raise ValueError("No data rows found in uploaded file.")

    header_idx, header_labels, header_score = detect_header_row(frame, required)
    if header_idx is None or header_score <= 0:
        raise ValueError(
            "Could not detect header row. Use columns: barcode, qty, department, article name, outlet"
        )

    seen = set()
    columns = []
    for col_idx, label in enumerate(header_labels):
        if label and label not in seen:
            columns.append(label)
            seen.add(label)
        else:
            columns.append(f"__extra_{col_idx}")

    data_frame = frame.iloc[header_idx + 1 :].copy()
    data_frame.columns = columns
    rows = data_frame.to_dict(orient="records")
    headers = {c for c in columns if c in required}

    missing_headers = sorted(required - headers)
    if missing_headers:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(missing_headers)
            + ". Required: barcode, qty, department, article name, outlet"
        )
    if not rows:
        raise ValueError("No data rows found in uploaded file.")

    db = get_db()
    lookup = outlet_lookup()
    outlet_names = get_outlet_names()
    items = []
    errors = []
    actions = []
    data_start_row = int(header_idx) + 2
    for idx, row in enumerate(rows, start=data_start_row):
        normalized = {}
        for k, v in row.items():
            ckey = canonical_column_name(k)
            if ckey:
                normalized[ckey] = v
        barcode_raw = normalized.get("barcode")
        qty_raw = normalized.get("qty")
        department_raw = normalized.get("department")
        article_name_raw = normalized.get("article name")
        outlet_raw = normalized.get("outlet")

        barcode = "" if pd.isna(barcode_raw) else str(barcode_raw).strip()
        department = "" if pd.isna(department_raw) else str(department_raw).strip()
        article_name = "" if pd.isna(article_name_raw) else str(article_name_raw).strip()
        source_outlet = "" if pd.isna(outlet_raw) else str(outlet_raw).strip()

        row_missing = []
        if not barcode:
            row_missing.append("barcode")
        if qty_raw is None or (isinstance(qty_raw, float) and pd.isna(qty_raw)) or str(qty_raw).strip() == "":
            row_missing.append("qty")
        if not department:
            row_missing.append("department")
        if not article_name:
            row_missing.append("article name")
        if not source_outlet:
            row_missing.append("outlet")
        if row_missing:
            errors.append(f"Row {idx}: missing {', '.join(row_missing)}")
            continue

        qty_text = str(qty_raw).strip()
        try:
            qty_float = float(qty_text)
            if not qty_float.is_integer():
                raise ValueError
            qty = int(qty_float)
        except ValueError:
            errors.append(f"Row {idx}: qty '{qty_text}' must be a whole number")
            continue
        if qty < 0:
            errors.append(f"Row {idx}: qty cannot be negative")
            continue

        canonical_outlet, action = ensure_outlet_from_source(
            source_outlet, db, lookup, outlet_names
        )
        if action:
            actions.append(action)

        items.append(
            {
                "barcode": barcode,
                "qty": qty,
                "department": department,
                "article_name": article_name,
                "outlet": canonical_outlet,
            }
        )

    if errors:
        preview = "; ".join(errors[:8])
        remaining = len(errors) - 8
        if remaining > 0:
            preview += f"; and {remaining} more error(s)"
        raise ValueError("Upload validation failed: " + preview)
    if not items:
        raise ValueError("No valid rows found in uploaded file.")
    return items, actions


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Self-signup allowed only for sub auditors.
    outlets = get_outlet_names()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "").strip()
        outlet = request.form.get("outlet", "").strip()

        if not name or not phone or not password or not outlet:
            flash("All fields are required.", "danger")
            return render_template("signup.html", outlets=outlets)
        if outlet not in outlets:
            flash("Please select a valid outlet.", "danger")
            return render_template("signup.html", outlets=outlets)

        db = get_db()
        exists = db.execute("SELECT id FROM users WHERE phone = ?", (phone,)).fetchone()
        if exists:
            flash("Phone already registered.", "danger")
            return render_template("signup.html", outlets=outlets)

        db.execute(
            """
            INSERT INTO users (name, phone, password_hash, role, outlet, created_by_admin, created_at)
            VALUES (?, ?, ?, 'sub_auditor', ?, 0, ?)
            """,
            (name, phone, generate_password_hash(password), outlet, now_ts()),
        )
        db.commit()
        flash("Signup successful. Login now.", "success")
        return redirect(url_for("login"))

    if not outlets:
        flash("No outlets configured yet. Please ask admin to create outlet first.", "danger")
    return render_template("signup.html", outlets=outlets)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "").strip()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid phone or password.", "danger")
            return render_template("login.html")

        session["user_id"] = user["id"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_audits"))
    if user["role"] == "outlet_head":
        return redirect(url_for("outlet_audits"))
    return redirect(url_for("sub_assignments"))


# ---------------------------
# Admin routes
# ---------------------------
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_users():
    db = get_db()
    outlets = get_outlet_names()
    if request.method == "POST":
        form_type = request.form.get("form_type", "").strip()
        if form_type == "create_outlet":
            outlet_name = request.form.get("outlet_name", "").strip()
            if not outlet_name:
                flash("Outlet name is required.", "danger")
            else:
                try:
                    db.execute(
                        "INSERT INTO outlets (name, created_at) VALUES (?, ?)",
                        (outlet_name, now_ts()),
                    )
                    db.commit()
                    flash("Outlet created.", "success")
                except sqlite3.IntegrityError:
                    flash("Outlet already exists.", "danger")
        elif form_type == "create_alias":
            alias = request.form.get("alias", "").strip()
            outlet = request.form.get("outlet", "").strip()
            if not alias or not outlet:
                flash("Alias and outlet are required.", "danger")
            elif outlet not in outlets:
                flash("Please select a valid outlet.", "danger")
            else:
                try:
                    db.execute(
                        """
                        INSERT INTO outlet_aliases (alias, outlet_name, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (alias, outlet, now_ts()),
                    )
                    db.commit()
                    flash("Outlet alias created.", "success")
                except sqlite3.IntegrityError:
                    flash("Alias already exists.", "danger")
        elif form_type == "create_outlet_head":
            name = request.form.get("name", "").strip()
            phone = request.form.get("phone", "").strip()
            password = request.form.get("password", "").strip()
            outlet = request.form.get("outlet", "").strip()

            if not name or not phone or not password or not outlet:
                flash("All fields required for outlet head creation.", "danger")
            elif outlet not in outlets:
                flash("Please select a valid outlet.", "danger")
            else:
                exists = db.execute("SELECT id FROM users WHERE phone = ?", (phone,)).fetchone()
                if exists:
                    flash("Phone already exists.", "danger")
                else:
                    db.execute(
                        """
                        INSERT INTO users (name, phone, password_hash, role, outlet, created_by_admin, created_at)
                        VALUES (?, ?, ?, 'outlet_head', ?, 1, ?)
                        """,
                        (name, phone, generate_password_hash(password), outlet, now_ts()),
                    )
                    db.commit()
                    flash("Outlet head created.", "success")
        else:
            flash("Unknown form submission.", "danger")
        outlets = get_outlet_names()

    users = db.execute(
        """
        SELECT id, name, phone, role, outlet, created_at
        FROM users
        ORDER BY role, name
        """
    ).fetchall()
    aliases = db.execute(
        """
        SELECT alias, outlet_name, created_at
        FROM outlet_aliases
        ORDER BY outlet_name, alias
        """
    ).fetchall()
    return render_template("admin_users.html", users=users, outlets=outlets, aliases=aliases)


@app.route("/admin/audits")
@login_required
@role_required("admin")
def admin_audits():
    db = get_db()
    audits = db.execute(
        """
        SELECT a.*, u.name AS creator_name
        FROM audits a
        JOIN users u ON a.created_by = u.id
        ORDER BY a.id DESC
        """
    ).fetchall()
    return render_template("admin_audits.html", audits=audits)


@app.route("/admin/audits/sample-csv")
@login_required
@role_required("admin")
def admin_audit_sample_csv():
    outlets = get_outlet_names()
    sample_outlet = outlets[0] if outlets else "Sample Outlet"
    content = (
        "barcode,qty,department,article name,outlet\n"
        f"8901234567890,10,GROCERY,Sample Article,{sample_outlet}\n"
    )
    response = make_response(content)
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=audit_upload_sample.csv"
    return response


@app.route("/admin/audits/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_audit_new():
    outlets = get_outlet_names()
    if not outlets and request.method == "GET":
        flash("Create at least one outlet before creating an audit.", "danger")
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        tag_outlet = request.form.get("tag_outlet", "").strip()
        upload_file = request.files.get("audit_file")

        if not name or not start_date or not end_date or not tag_outlet or not upload_file:
            flash("Name, dates, outlet and file are required.", "danger")
            return render_template(
                "admin_audit_form.html",
                mode="create",
                audit=None,
                outlets=outlets,
                all_outlets_value=ALL_OUTLETS_VALUE,
            )
        if tag_outlet != ALL_OUTLETS_VALUE and tag_outlet not in outlets:
            flash("Please select a valid outlet.", "danger")
            return render_template(
                "admin_audit_form.html",
                mode="create",
                audit=None,
                outlets=outlets,
                all_outlets_value=ALL_OUTLETS_VALUE,
            )

        try:
            items, actions = parse_uploaded_items(upload_file)
        except Exception as ex:
            flash(str(ex), "danger")
            return render_template(
                "admin_audit_form.html",
                mode="create",
                audit=None,
                outlets=outlets,
                all_outlets_value=ALL_OUTLETS_VALUE,
            )
        if actions:
            created = sorted({a[1] for a in actions if a[0] == "created"})
            aliased = sorted({f"{a[1]} -> {a[2]}" for a in actions if a[0] == "alias"})
            parts = []
            if created:
                parts.append(f"Created outlets: {', '.join(created[:8])}")
            if aliased:
                parts.append(f"Created aliases: {', '.join(aliased[:8])}")
            if parts:
                flash(" | ".join(parts), "info")

        outlets = get_outlet_names()
        if tag_outlet != ALL_OUTLETS_VALUE and tag_outlet not in outlets:
            flash("Selected outlet was not found after processing upload.", "danger")
            return render_template(
                "admin_audit_form.html",
                mode="create",
                audit=None,
                outlets=outlets,
                all_outlets_value=ALL_OUTLETS_VALUE,
            )
        if tag_outlet != ALL_OUTLETS_VALUE:
            items = [i for i in items if i["outlet"] == tag_outlet]
            if not items:
                flash("No file rows matched the selected outlet.", "danger")
                return render_template(
                    "admin_audit_form.html",
                    mode="create",
                    audit=None,
                    outlets=outlets,
                    all_outlets_value=ALL_OUTLETS_VALUE,
                )

        db = get_db()
        cur = db.execute(
            """
            INSERT INTO audits (name, description, start_date, end_date, tag_outlet, status, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (name, description, start_date, end_date, tag_outlet, session["user_id"], now_ts()),
        )
        audit_id = cur.lastrowid

        for item in items:
            db.execute(
                """
                INSERT OR IGNORE INTO audit_items (audit_id, barcode, expected_qty, department, article_name, outlet)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    item["barcode"],
                    item["qty"],
                    item["department"],
                    item["article_name"],
                    item["outlet"],
                ),
            )

        db.commit()
        flash("Audit created from CSV.", "success")
        return redirect(url_for("admin_audit_detail", audit_id=audit_id))

    return render_template(
        "admin_audit_form.html",
        mode="create",
        audit=None,
        outlets=outlets,
        all_outlets_value=ALL_OUTLETS_VALUE,
    )


@app.route("/admin/audits/<int:audit_id>")
@login_required
@role_required("admin")
def admin_audit_detail(audit_id):
    db = get_db()
    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for("admin_audits"))

    assignments = db.execute(
        """
        SELECT a.*, u.name AS sub_name
        FROM assignments a
        JOIN users u ON a.sub_auditor_id = u.id
        WHERE a.audit_id = ?
        ORDER BY a.outlet, a.department
        """,
        (audit_id,),
    ).fetchall()

    items_count = db.execute(
        "SELECT COUNT(*) AS c FROM audit_items WHERE audit_id = ?", (audit_id,)
    ).fetchone()["c"]
    scans_count = db.execute(
        "SELECT COUNT(*) AS c FROM scans WHERE audit_id = ?", (audit_id,)
    ).fetchone()["c"]

    return render_template(
        "admin_audit_detail.html",
        audit=audit,
        assignments=assignments,
        items_count=items_count,
        scans_count=scans_count,
    )


@app.route("/admin/audits/<int:audit_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_audit_edit(audit_id):
    db = get_db()
    outlets = get_outlet_names()
    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for("admin_audits"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        tag_outlet = request.form.get("tag_outlet", "").strip()

        if not name or not start_date or not end_date or not tag_outlet:
            flash("Required fields missing.", "danger")
        elif tag_outlet != ALL_OUTLETS_VALUE and tag_outlet not in outlets:
            flash("Please select a valid outlet.", "danger")
        else:
            db.execute(
                """
                UPDATE audits
                SET name = ?, description = ?, start_date = ?, end_date = ?, tag_outlet = ?
                WHERE id = ?
                """,
                (name, description, start_date, end_date, tag_outlet, audit_id),
            )
            db.commit()
            flash("Audit updated.", "success")
            return redirect(url_for("admin_audit_detail", audit_id=audit_id))

    return render_template(
        "admin_audit_form.html",
        mode="edit",
        audit=audit,
        outlets=outlets,
        all_outlets_value=ALL_OUTLETS_VALUE,
    )


@app.route("/admin/audits/<int:audit_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_audit_delete(audit_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE audit_id = ?", (audit_id,))
    db.execute("DELETE FROM assignments WHERE audit_id = ?", (audit_id,))
    db.execute("DELETE FROM audit_items WHERE audit_id = ?", (audit_id,))
    db.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
    db.commit()
    flash("Audit deleted.", "success")
    return redirect(url_for("admin_audits"))


@app.route("/admin/audits/<int:audit_id>/end", methods=["POST"])
@login_required
@role_required("admin")
def admin_audit_end(audit_id):
    db = get_db()
    db.execute("UPDATE audits SET status = 'ended' WHERE id = ?", (audit_id,))
    db.commit()
    flash("Audit marked as ended.", "success")
    return redirect(url_for("admin_audit_detail", audit_id=audit_id))


@app.route("/admin/assignments/<int:assignment_id>/toggle-unfreeze", methods=["POST"])
@login_required
@role_required("admin")
def admin_toggle_unfreeze(assignment_id):
    db = get_db()
    assignment = db.execute(
        "SELECT * FROM assignments WHERE id = ?", (assignment_id,)
    ).fetchone()
    if not assignment:
        flash("Assignment not found.", "danger")
        return redirect(url_for("admin_audits"))

    next_value = 0 if assignment["is_frozen"] else 1
    frozen_at = None if next_value == 0 else now_ts()
    db.execute(
        "UPDATE assignments SET is_frozen = ?, frozen_at = ? WHERE id = ?",
        (next_value, frozen_at, assignment_id),
    )
    db.commit()
    flash("Assignment status updated.", "success")
    return redirect(url_for("admin_audit_detail", audit_id=assignment["audit_id"]))


@app.route("/admin/audits/<int:audit_id>/export")
@login_required
@role_required("admin")
def admin_audit_export(audit_id):
    db = get_db()
    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for("admin_audits"))

    rows = db.execute(
        """
        SELECT
            ai.barcode,
            ai.article_name,
            ai.department,
            ai.outlet,
            ai.expected_qty,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty,
            (COALESCE(SUM(s.scanned_qty), 0) - ai.expected_qty) AS variance
        FROM audit_items ai
        LEFT JOIN scans s
          ON s.audit_id = ai.audit_id
         AND s.barcode = ai.barcode
         AND s.outlet = ai.outlet
         AND s.department = ai.department
        WHERE ai.audit_id = ?
        GROUP BY ai.barcode, ai.article_name, ai.department, ai.outlet, ai.expected_qty
        ORDER BY ai.department, ai.article_name
        """,
        (audit_id,),
    ).fetchall()

    df = pd.DataFrame([dict(r) for r in rows])
    temp_path = os.path.join(DATA_DIR, f"audit_{audit_id}_results.xlsx")
    df.to_excel(temp_path, index=False)

    return send_file(temp_path, as_attachment=True, download_name=f"audit_{audit_id}_results.xlsx")


@app.route("/admin/audits/<int:audit_id>/view")
@login_required
@role_required("admin")
def admin_audit_view(audit_id):
    db = get_db()
    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for("admin_audits"))

    rows = db.execute(
        """
        SELECT
            ai.outlet,
            ai.department,
            ai.barcode,
            ai.article_name,
            ai.expected_qty,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty,
            (COALESCE(SUM(s.scanned_qty), 0) - ai.expected_qty) AS variance
        FROM audit_items ai
        LEFT JOIN scans s
          ON s.audit_id = ai.audit_id
         AND s.barcode = ai.barcode
         AND s.outlet = ai.outlet
         AND s.department = ai.department
        WHERE ai.audit_id = ?
        GROUP BY ai.outlet, ai.department, ai.barcode, ai.article_name, ai.expected_qty
        ORDER BY ai.outlet, ai.department, ai.article_name
        """,
        (audit_id,),
    ).fetchall()

    return render_template("admin_audit_view.html", audit=audit, rows=rows)


# ---------------------------
# Outlet head routes
# ---------------------------
@app.route("/outlet/audits")
@login_required
@role_required("outlet_head")
def outlet_audits():
    user = current_user()
    db = get_db()
    audits = db.execute(
        """
        SELECT *
        FROM audits
        WHERE tag_outlet = ? OR tag_outlet = ?
        ORDER BY id DESC
        """,
        (user["outlet"], ALL_OUTLETS_VALUE),
    ).fetchall()
    return render_template("outlet_audits.html", audits=audits)


@app.route("/outlet/audits/<int:audit_id>/assign", methods=["GET", "POST"])
@login_required
@role_required("outlet_head")
def outlet_assign(audit_id):
    user = current_user()
    db = get_db()

    audit = db.execute(
        "SELECT * FROM audits WHERE id = ? AND (tag_outlet = ? OR tag_outlet = ?)",
        (audit_id, user["outlet"], ALL_OUTLETS_VALUE),
    ).fetchone()
    if not audit:
        flash("Audit not found for your outlet.", "danger")
        return redirect(url_for("outlet_audits"))

    departments = db.execute(
        """
        SELECT DISTINCT department
        FROM audit_items
        WHERE audit_id = ? AND outlet = ?
        ORDER BY department
        """,
        (audit_id, user["outlet"]),
    ).fetchall()

    sub_auditors = db.execute(
        """
        SELECT id, name, outlet
        FROM users
        WHERE role = 'sub_auditor' AND outlet = ?
        ORDER BY name
        """,
        (user["outlet"],),
    ).fetchall()

    if request.method == "POST":
        department = request.form.get("department", "").strip()
        sub_auditor_id = request.form.get("sub_auditor_id", "").strip()

        if not department or not sub_auditor_id:
            flash("Select department and sub-auditor.", "danger")
        else:
            try:
                db.execute(
                    """
                    INSERT INTO assignments (audit_id, outlet, department, sub_auditor_id, assigned_by, is_frozen, frozen_at)
                    VALUES (?, ?, ?, ?, ?, 0, NULL)
                    ON CONFLICT(audit_id, outlet, department)
                    DO UPDATE SET
                        sub_auditor_id = excluded.sub_auditor_id,
                        assigned_by = excluded.assigned_by,
                        is_frozen = 0,
                        frozen_at = NULL
                    """,
                    (
                        audit_id,
                        user["outlet"],
                        department,
                        int(sub_auditor_id),
                        user["id"],
                    ),
                )
                db.commit()
                flash("Department assigned.", "success")
            except sqlite3.IntegrityError:
                flash("Assignment failed. Check sub-auditor selection.", "danger")

    current_assignments = db.execute(
        """
        SELECT a.*, u.name AS sub_name
        FROM assignments a
        JOIN users u ON u.id = a.sub_auditor_id
        WHERE a.audit_id = ? AND a.outlet = ?
        ORDER BY a.department
        """,
        (audit_id, user["outlet"]),
    ).fetchall()

    return render_template(
        "outlet_assign.html",
        audit=audit,
        departments=departments,
        sub_auditors=sub_auditors,
        assignments=current_assignments,
    )


# ---------------------------
# Sub-auditor routes
# ---------------------------
@app.route("/sub/assignments")
@login_required
@role_required("sub_auditor")
def sub_assignments():
    user = current_user()
    db = get_db()
    assignments = db.execute(
        """
        SELECT a.*, au.name AS audit_name, au.tag_outlet, au.status
        FROM assignments a
        JOIN audits au ON au.id = a.audit_id
        WHERE a.sub_auditor_id = ?
        ORDER BY a.id DESC
        """,
        (user["id"],),
    ).fetchall()
    return render_template("sub_assignments.html", assignments=assignments)


@app.route("/sub/assignments/<int:assignment_id>/scan", methods=["GET", "POST"])
@login_required
@role_required("sub_auditor")
def sub_scan(assignment_id):
    user = current_user()
    db = get_db()

    assignment = db.execute(
        """
        SELECT a.*, au.name AS audit_name, au.status
        FROM assignments a
        JOIN audits au ON au.id = a.audit_id
        WHERE a.id = ? AND a.sub_auditor_id = ?
        """,
        (assignment_id, user["id"]),
    ).fetchone()

    if not assignment:
        flash("Assignment not found.", "danger")
        return redirect(url_for("sub_assignments"))

    if request.method == "POST":
        if assignment["is_frozen"] or assignment["status"] == "ended":
            flash("This assignment is frozen or audit is ended.", "danger")
            return redirect(url_for("sub_scan", assignment_id=assignment_id))

        barcode = request.form.get("barcode", "").strip()
        qty_raw = request.form.get("qty", "1").strip()
        manual_entry = 1 if request.form.get("manual_entry") == "on" else 0

        if not barcode:
            flash("Barcode is required.", "danger")
            return redirect(url_for("sub_scan", assignment_id=assignment_id))

        try:
            qty = int(float(qty_raw))
        except ValueError:
            qty = 1
        qty = max(qty, 1)

        item = db.execute(
            """
            SELECT *
            FROM audit_items
            WHERE audit_id = ? AND outlet = ? AND barcode = ? AND department = ?
            """,
            (assignment["audit_id"], assignment["outlet"], barcode, assignment["department"]),
        ).fetchone()

        if not item:
            flash("Barcode not found in your department list.", "danger")
            return redirect(url_for("sub_scan", assignment_id=assignment_id))

        db.execute(
            """
            INSERT INTO scans (audit_id, barcode, outlet, department, scanned_qty, scanned_by, manual_entry, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assignment["audit_id"],
                barcode,
                assignment["outlet"],
                assignment["department"],
                qty,
                user["id"],
                manual_entry,
                now_ts(),
            ),
        )
        db.commit()
        flash("Scan recorded.", "success")
        return redirect(url_for("sub_scan", assignment_id=assignment_id))

    rows = db.execute(
        """
        SELECT
            ai.barcode,
            ai.article_name,
            ai.expected_qty,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty,
            (COALESCE(SUM(s.scanned_qty), 0) - ai.expected_qty) AS variance
        FROM audit_items ai
        LEFT JOIN scans s
          ON s.audit_id = ai.audit_id
         AND s.barcode = ai.barcode
         AND s.outlet = ai.outlet
         AND s.department = ai.department
        WHERE ai.audit_id = ? AND ai.outlet = ? AND ai.department = ?
        GROUP BY ai.barcode, ai.article_name, ai.expected_qty
        ORDER BY ai.article_name
        """,
        (assignment["audit_id"], assignment["outlet"], assignment["department"]),
    ).fetchall()

    return render_template("sub_scan.html", assignment=assignment, rows=rows)


@app.route("/sub/assignments/<int:assignment_id>/freeze", methods=["POST"])
@login_required
@role_required("sub_auditor")
def sub_freeze(assignment_id):
    user = current_user()
    db = get_db()
    assignment = db.execute(
        "SELECT * FROM assignments WHERE id = ? AND sub_auditor_id = ?",
        (assignment_id, user["id"]),
    ).fetchone()
    if not assignment:
        flash("Assignment not found.", "danger")
        return redirect(url_for("sub_assignments"))

    db.execute(
        "UPDATE assignments SET is_frozen = 1, frozen_at = ? WHERE id = ?",
        (now_ts(), assignment_id),
    )
    db.commit()
    flash("Assignment frozen. Admin can unfreeze if needed.", "success")
    return redirect(url_for("sub_assignments"))


@app.context_processor
def inject_user():
    return {"session_user": current_user()}


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)




