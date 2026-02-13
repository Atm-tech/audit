# Aapoorti Audit Management MVP

## Features
- Role-based login: `admin`, `outlet_head`, `sub_auditor`
- Admin can:
  - Create outlet master and outlet aliases
  - Create audit (name, description, date range, tagged outlet, CSV upload)
  - Edit/delete/end audit
  - Create outlet heads
  - Unfreeze/freeze department assignments
  - Download final result in Excel
- Outlet head can:
  - View only audits for their outlet
  - Assign departments to sub-auditors
- Sub-auditor can:
  - Signup with name/phone/password/outlet
  - View only assigned departments
  - Scan barcode or enter manually
  - Freeze their department after completion

## CSV/Excel Format
Headers required:
- `barcode`
- `qty`
- `department`
- `article name`
- `outlet`

Notes:
- Upload supports `.csv`, `.xls`, `.xlsx`
- `outlet` values are auto-mapped using configured outlet aliases
- For `All Outlets` audits, data is segregated by outlet in assignments/scans/results

## Run
```bash
pip install -r requirements.txt
python app.py
```

Open: `http://127.0.0.1:5000`

Default admin login:
- Name: `admin`
- Phone: `9111080628`
- Password: `1234`
