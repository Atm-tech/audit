import csv
import json
import base64
import difflib
import io
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
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
# Local-only persistent SQLite storage.
# If APP_DATA_DIR is set, it uses that fixed directory; otherwise it uses project folder.
DATA_DIR = os.getenv("APP_DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, "audit.db")
HISTORY_DATABASE = os.path.join(DATA_DIR, "history.db")
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


def get_history_conn():
    conn = sqlite3.connect(HISTORY_DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_history_db():
    conn = get_history_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS history_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_audit_id INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            tag_outlet TEXT NOT NULL,
            start_date TEXT,
            end_date TEXT,
            ended_at TEXT,
            archived_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS history_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_audit_id INTEGER NOT NULL,
            outlet TEXT NOT NULL,
            department TEXT NOT NULL,
            barcode TEXT NOT NULL,
            article_name TEXT NOT NULL,
            expected_qty INTEGER NOT NULL,
            scanned_qty INTEGER NOT NULL,
            variance INTEGER NOT NULL,
            FOREIGN KEY(history_audit_id) REFERENCES history_audits(id)
        );

        CREATE TABLE IF NOT EXISTS history_sub_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_audit_id INTEGER NOT NULL,
            sub_auditor_id INTEGER NOT NULL,
            sub_name TEXT NOT NULL,
            outlet TEXT NOT NULL,
            department TEXT NOT NULL,
            scans_count INTEGER NOT NULL,
            scanned_qty_total INTEGER NOT NULL,
            unique_barcodes INTEGER NOT NULL,
            first_scan_at TEXT,
            last_scan_at TEXT,
            frozen_at TEXT,
            FOREIGN KEY(history_audit_id) REFERENCES history_audits(id)
        );
        """
    )
    conn.commit()
    conn.close()


def archive_audit_to_history(audit_id):
    db = get_db()
    init_history_db()
    hconn = get_history_conn()

    existing = hconn.execute(
        "SELECT id FROM history_audits WHERE source_audit_id = ?",
        (audit_id,),
    ).fetchone()
    if existing:
        hconn.close()
        return

    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        hconn.close()
        return

    cur = hconn.execute(
        """
        INSERT INTO history_audits (
            source_audit_id, name, tag_outlet, start_date, end_date, ended_at, archived_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit["id"],
            audit["name"],
            audit["tag_outlet"],
            audit["start_date"],
            audit["end_date"],
            now_ts(),
            now_ts(),
        ),
    )
    history_audit_id = cur.lastrowid

    item_rows = db.execute(
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
        """,
        (audit_id,),
    ).fetchall()
    for r in item_rows:
        hconn.execute(
            """
            INSERT INTO history_items (
                history_audit_id, outlet, department, barcode, article_name, expected_qty, scanned_qty, variance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                history_audit_id,
                r["outlet"],
                r["department"],
                r["barcode"],
                r["article_name"],
                r["expected_qty"],
                r["scanned_qty"],
                r["variance"],
            ),
        )

    metric_rows = db.execute(
        """
        SELECT
            a.sub_auditor_id,
            u.name AS sub_name,
            a.outlet,
            a.department,
            COUNT(s.id) AS scans_count,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty_total,
            COUNT(DISTINCT s.barcode) AS unique_barcodes,
            MIN(s.scanned_at) AS first_scan_at,
            MAX(s.scanned_at) AS last_scan_at,
            a.frozen_at
        FROM assignments a
        JOIN users u ON u.id = a.sub_auditor_id
        LEFT JOIN scans s
          ON s.audit_id = a.audit_id
         AND s.outlet = a.outlet
         AND s.department = a.department
         AND s.scanned_by = a.sub_auditor_id
        WHERE a.audit_id = ?
        GROUP BY a.sub_auditor_id, u.name, a.outlet, a.department, a.frozen_at
        """,
        (audit_id,),
    ).fetchall()
    for r in metric_rows:
        hconn.execute(
            """
            INSERT INTO history_sub_metrics (
                history_audit_id, sub_auditor_id, sub_name, outlet, department,
                scans_count, scanned_qty_total, unique_barcodes, first_scan_at, last_scan_at, frozen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                history_audit_id,
                r["sub_auditor_id"],
                r["sub_name"],
                r["outlet"],
                r["department"],
                r["scans_count"],
                r["scanned_qty_total"],
                r["unique_barcodes"],
                r["first_scan_at"],
                r["last_scan_at"],
                r["frozen_at"],
            ),
        )

    hconn.commit()
    hconn.close()


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
            UNIQUE(audit_id, outlet, barcode, department),
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

        CREATE TABLE IF NOT EXISTS scanner_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT,
            details_json TEXT,
            snapshot_path TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(assignment_id) REFERENCES assignments(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    migrate_assignments_table(db)
    migrate_scans_table(db)
    migrate_audit_items_table(db)
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


def migrate_audit_items_table(db):
    row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_items'"
    ).fetchone()
    table_sql = (row["sql"] or "") if row else ""
    if "UNIQUE(audit_id, outlet, barcode, department)" in table_sql:
        return

    db.executescript(
        """
        ALTER TABLE audit_items RENAME TO audit_items_old;

        CREATE TABLE audit_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            barcode TEXT NOT NULL,
            expected_qty INTEGER NOT NULL,
            department TEXT NOT NULL,
            article_name TEXT NOT NULL,
            outlet TEXT NOT NULL,
            UNIQUE(audit_id, outlet, barcode, department),
            FOREIGN KEY(audit_id) REFERENCES audits(id)
        );
        """
    )
    db.execute(
        """
        INSERT OR IGNORE INTO audit_items
            (id, audit_id, barcode, expected_qty, department, article_name, outlet)
        SELECT
            id, audit_id, barcode, expected_qty, department, article_name, outlet
        FROM audit_items_old
        """
    )
    db.execute("DROP TABLE audit_items_old")


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
        init_history_db()
        app.config["DB_INITIALIZED"] = True


# ---------------------------
# Auth and role helpers
# ---------------------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_feedback_snapshot(data_url):
    if not data_url or not isinstance(data_url, str):
        return None
    if "," not in data_url:
        return None
    head, encoded = data_url.split(",", 1)
    if "base64" not in head:
        return None
    try:
        binary = base64.b64decode(encoded, validate=True)
    except Exception:
        return None
    if len(binary) > 250_000:
        return None
    rel_dir = os.path.join("scanner_debug")
    abs_dir = os.path.join(DATA_DIR, rel_dir)
    os.makedirs(abs_dir, exist_ok=True)
    fname = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.jpg"
    rel_path = os.path.join(rel_dir, fname)
    abs_path = os.path.join(DATA_DIR, rel_path)
    with open(abs_path, "wb") as f:
        f.write(binary)
    return rel_path


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
        if not current_user():
            session.clear()
            flash("Session expired. Please login again.", "danger")
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


EFFICIENCY_WINDOW_DAYS = 7


def efficiency_window_start(days=EFFICIENCY_WINDOW_DAYS):
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def efficiency_band(score):
    if score >= 80:
        return "success"
    if score >= 50:
        return "warning"
    return "danger"


def build_sub_auditor_efficiency_rows(db, start_ts, days=EFFICIENCY_WINDOW_DAYS, outlet=None, user_id=None):
    filters = ["u.role = 'sub_auditor'"]
    params = [start_ts]
    if outlet:
        filters.append("u.outlet = ?")
        params.append(outlet)
    if user_id:
        filters.append("u.id = ?")
        params.append(user_id)

    rows = db.execute(
        f"""
        SELECT
            u.id AS sub_id,
            u.name AS sub_name,
            u.outlet AS outlet,
            COALESCE(COUNT(s.id), 0) AS scans_count,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty_total,
            COALESCE(COUNT(DISTINCT s.barcode), 0) AS unique_barcodes,
            COALESCE(COUNT(DISTINCT substr(s.scanned_at, 1, 10)), 0) AS scan_days,
            MIN(s.scanned_at) AS first_scan_at,
            MAX(s.scanned_at) AS last_scan_at,
            (julianday(MAX(s.scanned_at)) - julianday(MIN(s.scanned_at))) * 24.0 * 60.0 AS active_minutes
        FROM users u
        LEFT JOIN scans s
          ON s.scanned_by = u.id
         AND s.scanned_at >= ?
        WHERE {" AND ".join(filters)}
        GROUP BY u.id, u.name, u.outlet
        ORDER BY scanned_qty_total DESC, scans_count DESC
        """,
        tuple(params),
    ).fetchall()

    result = []
    for row in rows:
        scans_count = int(row["scans_count"] or 0)
        scanned_qty_total = int(row["scanned_qty_total"] or 0)
        unique_barcodes = int(row["unique_barcodes"] or 0)
        scan_days = int(row["scan_days"] or 0)
        active_minutes = float(row["active_minutes"] or 0.0)
        active_hours = max(active_minutes / 60.0, 1 / 60) if scans_count else 0
        qty_per_hour = round(scanned_qty_total / active_hours, 2) if active_hours else 0
        diversity = min(1.0, (unique_barcodes / scans_count)) if scans_count else 0
        consistency = min(1.0, scan_days / days) if days else 0
        throughput_norm = min(1.0, qty_per_hour / 120) if qty_per_hour else 0
        volume_norm = min(1.0, scanned_qty_total / (days * 40)) if days else 0
        efficiency_score = round(
            (throughput_norm * 45) + (consistency * 25) + (diversity * 15) + (volume_norm * 15),
            2,
        )
        result.append(
            {
                "sub_id": int(row["sub_id"]),
                "sub_name": row["sub_name"],
                "outlet": row["outlet"] or "",
                "scans_count": scans_count,
                "scanned_qty_total": scanned_qty_total,
                "unique_barcodes": unique_barcodes,
                "scan_days": scan_days,
                "active_minutes": round(active_minutes, 2) if scans_count else 0,
                "qty_per_hour": qty_per_hour,
                "efficiency_score": efficiency_score,
                "efficiency_class": efficiency_band(efficiency_score),
            }
        )

    result.sort(key=lambda x: (x["efficiency_score"], x["scanned_qty_total"]), reverse=True)
    return result


def build_outlet_head_efficiency_rows(db, start_ts, days=EFFICIENCY_WINDOW_DAYS, user_id=None, outlet=None):
    filters = ["u.role = 'outlet_head'"]
    params = [start_ts, start_ts, start_ts, start_ts, start_ts, start_ts, start_ts]
    if user_id:
        filters.append("u.id = ?")
        params.append(user_id)
    if outlet:
        filters.append("u.outlet = ?")
        params.append(outlet)

    rows = db.execute(
        f"""
        SELECT
            u.id AS outlet_head_id,
            u.name AS outlet_head_name,
            u.outlet AS outlet,
            COUNT(DISTINCT a.id) AS assignments_total,
            COALESCE(COUNT(DISTINCT CASE WHEN a.frozen_at IS NOT NULL AND a.frozen_at >= ? THEN a.id END), 0) AS frozen_recent,
            COALESCE(SUM(CASE WHEN s.scanned_at >= ? THEN 1 ELSE 0 END), 0) AS scans_count,
            COALESCE(SUM(CASE WHEN s.scanned_at >= ? THEN s.scanned_qty ELSE 0 END), 0) AS scanned_qty_total,
            COALESCE(COUNT(DISTINCT CASE WHEN s.scanned_at >= ? THEN s.barcode END), 0) AS unique_barcodes,
            COALESCE(COUNT(DISTINCT CASE WHEN s.scanned_at >= ? THEN substr(s.scanned_at, 1, 10) END), 0) AS scan_days,
            (julianday(MAX(CASE WHEN s.scanned_at >= ? THEN s.scanned_at END)) - julianday(MIN(CASE WHEN s.scanned_at >= ? THEN s.scanned_at END))) * 24.0 * 60.0 AS active_minutes
        FROM users u
        LEFT JOIN assignments a
          ON a.assigned_by = u.id
        LEFT JOIN scans s
          ON s.audit_id = a.audit_id
         AND s.outlet = a.outlet
         AND s.department = a.department
        WHERE {" AND ".join(filters)}
        GROUP BY u.id, u.name, u.outlet
        ORDER BY scanned_qty_total DESC, scans_count DESC
        """,
        tuple(params),
    ).fetchall()

    result = []
    for row in rows:
        assignments_total = int(row["assignments_total"] or 0)
        frozen_recent = int(row["frozen_recent"] or 0)
        scans_count = int(row["scans_count"] or 0)
        scanned_qty_total = int(row["scanned_qty_total"] or 0)
        unique_barcodes = int(row["unique_barcodes"] or 0)
        scan_days = int(row["scan_days"] or 0)
        active_minutes = float(row["active_minutes"] or 0.0)
        active_hours = max(active_minutes / 60.0, 1 / 60) if scans_count else 0
        qty_per_hour = round(scanned_qty_total / active_hours, 2) if active_hours else 0
        freeze_rate = (frozen_recent / assignments_total) if assignments_total else 0
        consistency = min(1.0, scan_days / days) if days else 0
        throughput_norm = min(1.0, qty_per_hour / 250) if qty_per_hour else 0
        volume_norm = min(1.0, scanned_qty_total / (days * 120)) if days else 0
        efficiency_score = round(
            (throughput_norm * 40) + (freeze_rate * 30) + (consistency * 20) + (volume_norm * 10),
            2,
        )
        result.append(
            {
                "outlet_head_id": int(row["outlet_head_id"]),
                "outlet_head_name": row["outlet_head_name"],
                "outlet": row["outlet"] or "",
                "assignments_total": assignments_total,
                "frozen_recent": frozen_recent,
                "freeze_rate_pct": round(freeze_rate * 100, 2),
                "scans_count": scans_count,
                "scanned_qty_total": scanned_qty_total,
                "unique_barcodes": unique_barcodes,
                "scan_days": scan_days,
                "active_minutes": round(active_minutes, 2) if scans_count else 0,
                "qty_per_hour": qty_per_hour,
                "efficiency_score": efficiency_score,
                "efficiency_class": efficiency_band(efficiency_score),
            }
        )

    result.sort(key=lambda x: (x["efficiency_score"], x["scanned_qty_total"]), reverse=True)
    return result


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
    if not user:
        session.clear()
        return redirect(url_for("login"))
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


@app.route("/admin/analytics")
@login_required
@role_required("admin")
def admin_analytics():
    db = get_db()
    init_history_db()
    hconn = get_history_conn()

    totals = {
        "audits_total": db.execute("SELECT COUNT(*) c FROM audits").fetchone()["c"],
        "audits_ended": db.execute("SELECT COUNT(*) c FROM audits WHERE status='ended'").fetchone()["c"],
        "archived_audits": hconn.execute("SELECT COUNT(*) c FROM history_audits").fetchone()["c"],
        "sub_auditors": db.execute("SELECT COUNT(*) c FROM users WHERE role='sub_auditor'").fetchone()["c"],
    }
    totals_row = hconn.execute(
        """
        SELECT
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs_total,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items,
            COUNT(*) AS items_total
        FROM history_items
        """
    ).fetchone()
    totals["expected_total"] = int(totals_row["expected_total"] or 0)
    totals["scanned_total"] = int(totals_row["scanned_total"] or 0)
    totals["variance_abs_total"] = int(totals_row["variance_abs_total"] or 0)
    totals["perfect_items"] = int(totals_row["perfect_items"] or 0)
    totals["items_total"] = int(totals_row["items_total"] or 0)
    totals["completion_pct"] = round(
        (totals["scanned_total"] / totals["expected_total"]) * 100, 2
    ) if totals["expected_total"] else 0
    totals["perfect_match_pct"] = round(
        (totals["perfect_items"] / totals["items_total"]) * 100, 2
    ) if totals["items_total"] else 0

    outlet_perf_rows = hconn.execute(
        """
        SELECT outlet,
               COUNT(*) AS items_count,
               SUM(expected_qty) AS expected_total,
               SUM(scanned_qty) AS scanned_total,
               SUM(ABS(variance)) AS variance_abs,
               SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END) AS perfect_items
        FROM history_items
        GROUP BY outlet
        ORDER BY variance_abs DESC
        LIMIT 50
        """
    ).fetchall()
    outlet_perf = []
    for r in outlet_perf_rows:
        expected = int(r["expected_total"] or 0)
        scanned = int(r["scanned_total"] or 0)
        items_count = int(r["items_count"] or 0)
        perfect_items = int(r["perfect_items"] or 0)
        outlet_perf.append(
            {
                "outlet": r["outlet"],
                "items_count": items_count,
                "expected_total": expected,
                "scanned_total": scanned,
                "variance_abs": int(r["variance_abs"] or 0),
                "completion_pct": round((scanned / expected) * 100, 2) if expected else 0,
                "perfect_pct": round((perfect_items / items_count) * 100, 2) if items_count else 0,
            }
        )

    department_perf = hconn.execute(
        """
        SELECT
            outlet,
            department,
            COUNT(*) AS items_count,
            SUM(expected_qty) AS expected_total,
            SUM(scanned_qty) AS scanned_total,
            SUM(ABS(variance)) AS variance_abs
        FROM history_items
        GROUP BY outlet, department
        ORDER BY variance_abs DESC, expected_total DESC
        LIMIT 100
        """
    ).fetchall()

    trend_rows = hconn.execute(
        """
        SELECT
            substr(archived_at, 1, 7) AS month_key,
            COUNT(*) AS audits_count
        FROM history_audits
        GROUP BY month_key
        ORDER BY month_key DESC
        LIMIT 12
        """
    ).fetchall()

    window_start = efficiency_window_start(EFFICIENCY_WINDOW_DAYS)
    sub_eff = build_sub_auditor_efficiency_rows(
        db=db,
        start_ts=window_start,
        days=EFFICIENCY_WINDOW_DAYS,
    )
    outlet_head_eff = build_outlet_head_efficiency_rows(
        db=db,
        start_ts=window_start,
        days=EFFICIENCY_WINDOW_DAYS,
    )
    hconn.close()
    return render_template(
        "admin_analytics.html",
        totals=totals,
        outlet_perf=outlet_perf,
        department_perf=department_perf,
        trend_rows=trend_rows,
        sub_eff=sub_eff,
        outlet_head_eff=outlet_head_eff,
        efficiency_window_days=EFFICIENCY_WINDOW_DAYS,
    )


@app.route("/admin/history")
@login_required
@role_required("admin")
def admin_history():
    init_history_db()
    hconn = get_history_conn()
    rows = hconn.execute(
        """
        SELECT
            ha.*,
            (SELECT COUNT(*) FROM history_items hi WHERE hi.history_audit_id = ha.id) AS items_count,
            (SELECT SUM(ABS(variance)) FROM history_items hi WHERE hi.history_audit_id = ha.id) AS variance_abs
        FROM history_audits ha
        ORDER BY ha.id DESC
        """
    ).fetchall()
    hconn.close()
    return render_template("admin_history.html", rows=rows)


@app.route("/admin/history/<int:history_audit_id>/purge", methods=["POST"])
@login_required
@role_required("admin")
def admin_history_purge(history_audit_id):
    init_history_db()
    hconn = get_history_conn()
    hconn.execute("DELETE FROM history_sub_metrics WHERE history_audit_id = ?", (history_audit_id,))
    hconn.execute("DELETE FROM history_items WHERE history_audit_id = ?", (history_audit_id,))
    hconn.execute("DELETE FROM history_audits WHERE id = ?", (history_audit_id,))
    hconn.commit()
    hconn.close()
    flash("Historical audit purged.", "success")
    return redirect(url_for("admin_history"))


@app.route("/admin/scanner-feedback")
@login_required
@role_required("admin")
def admin_scanner_feedback():
    db = get_db()
    rows = db.execute(
        """
        SELECT
            sf.*,
            u.name AS sub_name,
            a.department,
            a.outlet,
            au.name AS audit_name
        FROM scanner_feedback sf
        JOIN users u ON u.id = sf.user_id
        JOIN assignments a ON a.id = sf.assignment_id
        JOIN audits au ON au.id = a.audit_id
        ORDER BY sf.id DESC
        LIMIT 300
        """
    ).fetchall()
    return render_template("admin_scanner_feedback.html", rows=rows)


@app.route("/admin/scanner-feedback/snapshot/<path:filename>")
@login_required
@role_required("admin")
def static_scanner_snapshot(filename):
    safe_rel = os.path.normpath(filename).replace("\\", "/")
    if safe_rel.startswith(".."):
        return "invalid path", 400
    abs_path = os.path.join(DATA_DIR, safe_rel)
    if not os.path.exists(abs_path):
        return "not found", 404
    return send_file(abs_path)


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


@app.route("/admin/audits/<int:audit_id>/analytics")
@login_required
@role_required("admin")
def admin_audit_analytics(audit_id):
    db = get_db()
    audit = db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not audit:
        flash("Audit not found.", "danger")
        return redirect(url_for("admin_audits"))

    item_metrics_sql = """
        WITH item_metrics AS (
            SELECT
                ai.outlet,
                ai.department,
                ai.barcode,
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
            GROUP BY ai.outlet, ai.department, ai.barcode, ai.expected_qty
        )
    """

    totals_row = db.execute(
        item_metrics_sql
        + """
        SELECT
            COUNT(*) AS items_count,
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items
        FROM item_metrics
        """,
        (audit_id,),
    ).fetchone()

    totals = {
        "items_count": int(totals_row["items_count"] or 0),
        "expected_total": int(totals_row["expected_total"] or 0),
        "scanned_total": int(totals_row["scanned_total"] or 0),
        "variance_abs": int(totals_row["variance_abs"] or 0),
        "perfect_items": int(totals_row["perfect_items"] or 0),
    }
    totals["completion_pct"] = (
        round((totals["scanned_total"] / totals["expected_total"]) * 100, 2)
        if totals["expected_total"]
        else 0
    )
    totals["perfect_pct"] = (
        round((totals["perfect_items"] / totals["items_count"]) * 100, 2)
        if totals["items_count"]
        else 0
    )
    assignments_row = db.execute(
        """
        SELECT
            COUNT(*) AS assignments_total,
            COALESCE(SUM(CASE WHEN is_frozen = 1 THEN 1 ELSE 0 END), 0) AS assignments_frozen,
            COUNT(DISTINCT sub_auditor_id) AS sub_auditors_assigned
        FROM assignments
        WHERE audit_id = ?
        """,
        (audit_id,),
    ).fetchone()
    assignment_summary = {
        "assignments_total": int(assignments_row["assignments_total"] or 0),
        "assignments_frozen": int(assignments_row["assignments_frozen"] or 0),
        "sub_auditors_assigned": int(assignments_row["sub_auditors_assigned"] or 0),
    }
    assignment_summary["freeze_completion_pct"] = (
        round(
            (assignment_summary["assignments_frozen"] / assignment_summary["assignments_total"]) * 100,
            2,
        )
        if assignment_summary["assignments_total"]
        else 0
    )

    scan_row = db.execute(
        """
        SELECT
            COUNT(*) AS scans_count,
            COALESCE(SUM(scanned_qty), 0) AS scanned_qty_total,
            COUNT(DISTINCT barcode) AS unique_barcodes,
            COALESCE(SUM(CASE WHEN manual_entry = 1 THEN 1 ELSE 0 END), 0) AS manual_entries
        FROM scans
        WHERE audit_id = ?
        """,
        (audit_id,),
    ).fetchone()
    scan_summary = {
        "scans_count": int(scan_row["scans_count"] or 0),
        "scanned_qty_total": int(scan_row["scanned_qty_total"] or 0),
        "unique_barcodes": int(scan_row["unique_barcodes"] or 0),
        "manual_entries": int(scan_row["manual_entries"] or 0),
    }
    scan_summary["manual_entry_pct"] = (
        round((scan_summary["manual_entries"] / scan_summary["scans_count"]) * 100, 2)
        if scan_summary["scans_count"]
        else 0
    )

    def with_percentages(rows):
        result = []
        for row in rows:
            expected_total = int(row["expected_total"] or 0)
            scanned_total = int(row["scanned_total"] or 0)
            items_count = int(row["items_count"] or 0)
            perfect_items = int(row["perfect_items"] or 0)
            result.append(
                {
                    **dict(row),
                    "items_count": items_count,
                    "expected_total": expected_total,
                    "scanned_total": scanned_total,
                    "variance_abs": int(row["variance_abs"] or 0),
                    "completion_pct": round((scanned_total / expected_total) * 100, 2)
                    if expected_total
                    else 0,
                    "perfect_pct": round((perfect_items / items_count) * 100, 2)
                    if items_count
                    else 0,
                }
            )
        return result

    outlet_rows = db.execute(
        item_metrics_sql
        + """
        SELECT
            outlet,
            COUNT(*) AS items_count,
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items
        FROM item_metrics
        GROUP BY outlet
        ORDER BY variance_abs DESC, expected_total DESC
        """,
        (audit_id,),
    ).fetchall()

    department_rows = db.execute(
        item_metrics_sql
        + """
        SELECT
            department,
            COUNT(*) AS items_count,
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items
        FROM item_metrics
        GROUP BY department
        ORDER BY variance_abs DESC, expected_total DESC
        """,
        (audit_id,),
    ).fetchall()

    outlet_department_rows = db.execute(
        item_metrics_sql
        + """
        SELECT
            outlet,
            department,
            COUNT(*) AS items_count,
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items
        FROM item_metrics
        GROUP BY outlet, department
        ORDER BY variance_abs DESC, expected_total DESC
        """,
        (audit_id,),
    ).fetchall()

    sub_eff_rows = db.execute(
        """
        SELECT
            a.sub_auditor_id,
            u.name AS sub_name,
            a.outlet,
            COUNT(DISTINCT a.id) AS assignments_total,
            COALESCE(SUM(CASE WHEN a.is_frozen = 1 THEN 1 ELSE 0 END), 0) AS assignments_frozen,
            COUNT(s.id) AS scans_count,
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty_total,
            COUNT(DISTINCT s.barcode) AS unique_barcodes,
            MIN(s.scanned_at) AS first_scan_at,
            MAX(s.scanned_at) AS last_scan_at,
            (julianday(MAX(s.scanned_at)) - julianday(MIN(s.scanned_at))) * 24.0 * 60.0 AS active_minutes
        FROM assignments a
        JOIN users u ON u.id = a.sub_auditor_id
        LEFT JOIN scans s
          ON s.audit_id = a.audit_id
         AND s.outlet = a.outlet
         AND s.department = a.department
         AND s.scanned_by = a.sub_auditor_id
        WHERE a.audit_id = ?
        GROUP BY a.sub_auditor_id, u.name, a.outlet
        ORDER BY scanned_qty_total DESC, scans_count DESC, assignments_total DESC
        """,
        (audit_id,),
    ).fetchall()
    max_scanned_qty = max([int(r["scanned_qty_total"] or 0) for r in sub_eff_rows], default=0)
    max_assignments = max([int(r["assignments_total"] or 0) for r in sub_eff_rows], default=0)
    sub_eff = []
    for r in sub_eff_rows:
        assignments_total = int(r["assignments_total"] or 0)
        assignments_frozen = int(r["assignments_frozen"] or 0)
        scans_count = int(r["scans_count"] or 0)
        scanned_qty_total = int(r["scanned_qty_total"] or 0)
        unique_barcodes = int(r["unique_barcodes"] or 0)
        completion_rate = (assignments_frozen / assignments_total) if assignments_total else 0
        throughput_norm = (scanned_qty_total / max_scanned_qty) if max_scanned_qty else 0
        coverage_norm = (assignments_total / max_assignments) if max_assignments else 0
        diversity = min(1.0, (unique_barcodes / scans_count)) if scans_count else 0
        active_minutes = round(float(r["active_minutes"] or 0), 2) if r["active_minutes"] else 0
        efficiency_score = round(
            (throughput_norm * 35) + (coverage_norm * 20) + (completion_rate * 25) + (diversity * 20), 2
        )
        sub_eff.append(
            {
                "sub_name": r["sub_name"],
                "outlet": r["outlet"],
                "assignments_total": assignments_total,
                "assignments_frozen": assignments_frozen,
                "completion_pct": round(completion_rate * 100, 2),
                "scans_count": scans_count,
                "scanned_qty_total": scanned_qty_total,
                "unique_barcodes": unique_barcodes,
                "active_minutes": active_minutes,
                "efficiency_score": efficiency_score,
            }
        )
    sub_eff.sort(key=lambda x: (x["efficiency_score"], x["scanned_qty_total"]), reverse=True)

    return render_template(
        "admin_audit_analytics.html",
        audit=audit,
        totals=totals,
        assignment_summary=assignment_summary,
        scan_summary=scan_summary,
        outlet_rows=with_percentages(outlet_rows),
        department_rows=with_percentages(department_rows),
        outlet_department_rows=with_percentages(outlet_department_rows),
        sub_eff=sub_eff,
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
    archive_audit_to_history(audit_id)
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


@app.route("/outlet/analytics")
@login_required
@role_required("outlet_head")
def outlet_analytics():
    user = current_user()
    db = get_db()
    outlet = user["outlet"]
    init_history_db()
    hconn = get_history_conn()
    totals_row = hconn.execute(
        """
        SELECT
            COUNT(*) AS items_count,
            COALESCE(SUM(expected_qty), 0) AS expected_total,
            COALESCE(SUM(scanned_qty), 0) AS scanned_total,
            COALESCE(SUM(ABS(variance)), 0) AS variance_abs,
            COALESCE(SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END), 0) AS perfect_items
        FROM history_items
        WHERE outlet = ?
        """,
        (outlet,),
    ).fetchone()
    totals = {
        "items_count": int(totals_row["items_count"] or 0),
        "expected_total": int(totals_row["expected_total"] or 0),
        "scanned_total": int(totals_row["scanned_total"] or 0),
        "variance_abs": int(totals_row["variance_abs"] or 0),
        "perfect_items": int(totals_row["perfect_items"] or 0),
    }
    totals["completion_pct"] = round(
        (totals["scanned_total"] / totals["expected_total"]) * 100, 2
    ) if totals["expected_total"] else 0
    totals["perfect_pct"] = round(
        (totals["perfect_items"] / totals["items_count"]) * 100, 2
    ) if totals["items_count"] else 0

    rows = hconn.execute(
        """
        SELECT
            department,
            COUNT(*) AS items_count,
            SUM(expected_qty) AS expected_total,
            SUM(scanned_qty) AS scanned_total,
            SUM(ABS(variance)) AS variance_abs,
            SUM(CASE WHEN variance = 0 THEN 1 ELSE 0 END) AS perfect_items
        FROM history_items
        WHERE outlet = ?
        GROUP BY department
        ORDER BY variance_abs DESC
        """,
        (outlet,),
    ).fetchall()
    window_start = efficiency_window_start(EFFICIENCY_WINDOW_DAYS)
    sub_eff = build_sub_auditor_efficiency_rows(
        db=db,
        start_ts=window_start,
        days=EFFICIENCY_WINDOW_DAYS,
        outlet=outlet,
    )
    manager_rows = build_outlet_head_efficiency_rows(
        db=db,
        start_ts=window_start,
        days=EFFICIENCY_WINDOW_DAYS,
        user_id=user["id"],
    )
    manager_eff = manager_rows[0] if manager_rows else None
    hconn.close()
    return render_template(
        "outlet_analytics.html",
        outlet=outlet,
        totals=totals,
        rows=rows,
        sub_eff=sub_eff,
        manager_eff=manager_eff,
        efficiency_window_days=EFFICIENCY_WINDOW_DAYS,
    )


@app.route("/outlet/audits/<int:audit_id>/view")
@login_required
@role_required("outlet_head")
def outlet_audit_view(audit_id):
    user = current_user()
    db = get_db()
    audit = db.execute(
        "SELECT * FROM audits WHERE id = ? AND (tag_outlet = ? OR tag_outlet = ?)",
        (audit_id, user["outlet"], ALL_OUTLETS_VALUE),
    ).fetchone()
    if not audit:
        flash("Audit not found for your outlet.", "danger")
        return redirect(url_for("outlet_audits"))

    rows = db.execute(
        """
        SELECT
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
        WHERE ai.audit_id = ? AND ai.outlet = ?
        GROUP BY ai.department, ai.barcode, ai.article_name, ai.expected_qty
        ORDER BY ai.department, ai.article_name
        """,
        (audit_id, user["outlet"]),
    ).fetchall()

    return render_template("outlet_audit_view.html", audit=audit, rows=rows, outlet=user["outlet"])


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
            existing_assignment = db.execute(
                """
                SELECT id, is_frozen
                FROM assignments
                WHERE audit_id = ? AND outlet = ? AND department = ?
                """,
                (audit_id, user["outlet"], department),
            ).fetchone()
            if existing_assignment and int(existing_assignment["is_frozen"] or 0) == 1:
                flash("This department is frozen. Only admin can unfreeze it.", "danger")
                return redirect(url_for("outlet_assign", audit_id=audit_id))
            try:
                db.execute(
                    """
                    INSERT INTO assignments (audit_id, outlet, department, sub_auditor_id, assigned_by, is_frozen, frozen_at)
                    VALUES (?, ?, ?, ?, ?, 0, NULL)
                    ON CONFLICT(audit_id, outlet, department)
                    DO UPDATE SET
                        sub_auditor_id = excluded.sub_auditor_id,
                        assigned_by = excluded.assigned_by
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
    assignment_rows = db.execute(
        """
        SELECT
            a.*,
            au.name AS audit_name,
            au.tag_outlet,
            au.status,
            COALESCE(ai.expected_total, 0) AS expected_total,
            COALESCE(ss.scanned_total, 0) AS scanned_total,
            COALESCE(ss.scans_count, 0) AS scans_count,
            COALESCE(ss.unique_barcodes, 0) AS unique_barcodes
        FROM assignments a
        JOIN audits au ON au.id = a.audit_id
        LEFT JOIN (
            SELECT
                audit_id,
                outlet,
                department,
                SUM(expected_qty) AS expected_total
            FROM audit_items
            GROUP BY audit_id, outlet, department
        ) ai
          ON ai.audit_id = a.audit_id
         AND ai.outlet = a.outlet
         AND ai.department = a.department
        LEFT JOIN (
            SELECT
                audit_id,
                outlet,
                department,
                scanned_by,
                SUM(scanned_qty) AS scanned_total,
                COUNT(*) AS scans_count,
                COUNT(DISTINCT barcode) AS unique_barcodes
            FROM scans
            GROUP BY audit_id, outlet, department, scanned_by
        ) ss
          ON ss.audit_id = a.audit_id
         AND ss.outlet = a.outlet
         AND ss.department = a.department
         AND ss.scanned_by = a.sub_auditor_id
        WHERE a.sub_auditor_id = ?
        ORDER BY a.id DESC
        """,
        (user["id"],),
    ).fetchall()

    assignments = []
    for row in assignment_rows:
        expected_total = int(row["expected_total"] or 0)
        scanned_total = int(row["scanned_total"] or 0)
        raw_progress_pct = round((scanned_total / expected_total) * 100, 2) if expected_total else 0
        progress_pct = min(100, raw_progress_pct)
        efficiency_score = round(
            ((min(1.0, scanned_total / expected_total) if expected_total else 0) * 85)
            + (15 if row["is_frozen"] else 0),
            2,
        )
        efficiency_class = efficiency_band(efficiency_score)
        assignments.append(
            {
                **dict(row),
                "expected_total": expected_total,
                "scanned_total": scanned_total,
                "raw_progress_pct": raw_progress_pct,
                "progress_pct": progress_pct,
                "efficiency_score": efficiency_score,
                "efficiency_class": efficiency_class,
            }
        )

    departments_total = len(assignments)
    departments_scanned = sum(1 for a in assignments if a["scanned_total"] > 0)
    departments_completed = sum(
        1
        for a in assignments
        if a["is_frozen"] or (a["expected_total"] > 0 and a["scanned_total"] >= a["expected_total"])
    )
    assignments_frozen = sum(1 for a in assignments if a["is_frozen"])
    expected_total = sum(a["expected_total"] for a in assignments)
    scanned_total = sum(a["scanned_total"] for a in assignments)
    scans_count = sum(int(a["scans_count"] or 0) for a in assignments)
    unique_barcodes = sum(int(a["unique_barcodes"] or 0) for a in assignments)

    dept_completion_pct = round((departments_completed / departments_total) * 100, 2) if departments_total else 0
    qty_completion_pct = round((scanned_total / expected_total) * 100, 2) if expected_total else 0
    freeze_completion_pct = round((assignments_frozen / departments_total) * 100, 2) if departments_total else 0
    scan_coverage_pct = round((departments_scanned / departments_total) * 100, 2) if departments_total else 0
    efficiency_score = round(
        (min(100, qty_completion_pct) * 0.45)
        + (dept_completion_pct * 0.30)
        + (scan_coverage_pct * 0.15)
        + (freeze_completion_pct * 0.10),
        2,
    )
    efficiency_class = efficiency_band(efficiency_score)

    window_start = efficiency_window_start(EFFICIENCY_WINDOW_DAYS)
    sub_timebound = build_sub_auditor_efficiency_rows(
        db=db,
        start_ts=window_start,
        days=EFFICIENCY_WINDOW_DAYS,
        user_id=user["id"],
    )
    my_timebound = sub_timebound[0] if sub_timebound else {
        "efficiency_score": 0,
        "efficiency_class": "danger",
        "qty_per_hour": 0,
        "scan_days": 0,
        "active_minutes": 0,
        "scans_count": 0,
        "scanned_qty_total": 0,
        "unique_barcodes": 0,
    }

    overview = {
        "departments_total": departments_total,
        "departments_scanned": departments_scanned,
        "departments_completed": departments_completed,
        "assignments_frozen": assignments_frozen,
        "expected_total": expected_total,
        "scanned_total": scanned_total,
        "scans_count": scans_count,
        "unique_barcodes": unique_barcodes,
        "dept_completion_pct": dept_completion_pct,
        "qty_completion_pct": qty_completion_pct,
        "freeze_completion_pct": freeze_completion_pct,
        "scan_coverage_pct": scan_coverage_pct,
        "efficiency_score": efficiency_score,
        "efficiency_class": efficiency_class,
        "tb_efficiency_score": my_timebound["efficiency_score"],
        "tb_efficiency_class": my_timebound["efficiency_class"],
        "tb_qty_per_hour": my_timebound["qty_per_hour"],
        "tb_scan_days": my_timebound["scan_days"],
        "tb_active_minutes": my_timebound["active_minutes"],
        "tb_scans_count": my_timebound["scans_count"],
        "tb_scanned_qty_total": my_timebound["scanned_qty_total"],
        "tb_unique_barcodes": my_timebound["unique_barcodes"],
        "efficiency_window_days": EFFICIENCY_WINDOW_DAYS,
    }
    return render_template("sub_assignments.html", assignments=assignments, overview=overview)


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
            COALESCE(SUM(s.scanned_qty), 0) AS scanned_qty
        FROM audit_items ai
        LEFT JOIN scans s
          ON s.audit_id = ai.audit_id
         AND s.barcode = ai.barcode
         AND s.outlet = ai.outlet
         AND s.department = ai.department
        WHERE ai.audit_id = ? AND ai.outlet = ? AND ai.department = ?
        GROUP BY ai.barcode, ai.article_name
        ORDER BY ai.article_name
        """,
        (assignment["audit_id"], assignment["outlet"], assignment["department"]),
    ).fetchall()

    return render_template("sub_scan.html", assignment=assignment, rows=rows)


@app.route("/sub/assignments/<int:assignment_id>/scanner-feedback", methods=["POST"])
@login_required
@role_required("sub_auditor")
def sub_scanner_feedback(assignment_id):
    user = current_user()
    db = get_db()
    assignment = db.execute(
        "SELECT * FROM assignments WHERE id = ? AND sub_auditor_id = ?",
        (assignment_id, user["id"]),
    ).fetchone()
    if not assignment:
        return {"ok": False, "error": "assignment-not-found"}, 404

    payload = request.get_json(silent=True) or {}
    event_type = str(payload.get("event", "unknown")).strip()[:50] or "unknown"
    message = str(payload.get("message", "")).strip()[:500]
    details = payload.get("details", {})
    snapshot = payload.get("snapshot")

    details_json = ""
    try:
        details_json = json.dumps(details, ensure_ascii=True)[:5000]
    except Exception:
        details_json = ""

    snapshot_path = save_feedback_snapshot(snapshot)
    db.execute(
        """
        INSERT INTO scanner_feedback (
            assignment_id, user_id, event_type, message, details_json, snapshot_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (assignment_id, user["id"], event_type, message, details_json, snapshot_path, now_ts()),
    )
    db.commit()
    return {"ok": True}


@app.route("/sub/assignments/<int:assignment_id>/freeze", methods=["POST"])
@login_required
@role_required("sub_auditor")
def sub_freeze(assignment_id):
    user = current_user()
    db = get_db()
    assignment = db.execute(
        """
        SELECT a.*, au.status
        FROM assignments a
        JOIN audits au ON au.id = a.audit_id
        WHERE a.id = ? AND a.sub_auditor_id = ?
        """,
        (assignment_id, user["id"]),
    ).fetchone()
    if not assignment:
        flash("Assignment not found.", "danger")
        return redirect(url_for("sub_assignments"))
    if assignment["status"] == "ended":
        flash("Audit is ended. Department cannot be frozen now.", "danger")
        return redirect(url_for("sub_assignments"))
    if assignment["is_frozen"]:
        flash("This department is already frozen. Only admin can unfreeze it.", "info")
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
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )






