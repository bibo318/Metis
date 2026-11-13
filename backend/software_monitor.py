"""Theo dõi phần mềm - giám sát CVE/ATTT theo danh sách tài sản phần mềm."""
import csv
import io
import json
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("metis.software_watch")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "software_watch.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sw_assets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    system_name      TEXT NOT NULL DEFAULT '',
    environment      TEXT NOT NULL DEFAULT '',
    software_name    TEXT NOT NULL DEFAULT '',
    vendor           TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '',
    cve_search_term  TEXT DEFAULT '',
    enabled          INTEGER NOT NULL DEFAULT 1,
    notes            TEXT DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sw_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    cve_id      TEXT NOT NULL DEFAULT '',
    title       TEXT DEFAULT '',
    severity    TEXT DEFAULT '',
    epss        REAL DEFAULT 0.0,
    is_kev      INTEGER DEFAULT 0,
    poc_count   INTEGER DEFAULT 0,
    published   TEXT DEFAULT '',
    source      TEXT DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'new',
    created_at  TEXT NOT NULL DEFAULT '',
    UNIQUE(asset_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_asset ON sw_alerts(asset_id);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_status ON sw_alerts(status);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_cve ON sw_alerts(cve_id);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_severity ON sw_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_asset_status ON sw_alerts(asset_id, status);
CREATE INDEX IF NOT EXISTS idx_sw_alerts_sort ON sw_alerts(is_kev DESC, epss DESC, created_at DESC);
CREATE TABLE IF NOT EXISTS sw_libraries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    system_name     TEXT NOT NULL DEFAULT '',
    library_name    TEXT NOT NULL DEFAULT '',
    stack           TEXT NOT NULL DEFAULT '',
    min_version     TEXT DEFAULT '',
    current_version TEXT DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'APPROVED',
    notes           TEXT DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sw_libs_system ON sw_libraries(system_name);
CREATE INDEX IF NOT EXISTS idx_sw_libs_status ON sw_libraries(status);
CREATE TABLE IF NOT EXISTS sw_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sw_version_cache (
    cve_id      TEXT PRIMARY KEY,
    affected_v  TEXT DEFAULT '',
    fixed_v     TEXT DEFAULT '',
    fetched_at  TEXT DEFAULT ''
);
"""

CSV_COLUMNS = [
    "Hệ thống thông tin thành phần",
    "Môi trường",
    "Tên phần mềm",
    "Hãng cung cấp",
    "Phiên bản prod",
]
CSV_COLUMNS_EN = [
    "System Name",
    "Environment",
    "Software Name",
    "Vendor",
    "Version",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        for col_def in [
            "ALTER TABLE sw_assets ADD COLUMN cve_search_term TEXT DEFAULT ''",
            "ALTER TABLE sw_assets ADD COLUMN latest_version TEXT DEFAULT ''",
            "ALTER TABLE sw_assets ADD COLUMN version_checked_at TEXT DEFAULT ''",
            "ALTER TABLE sw_alerts ADD COLUMN affected_versions TEXT DEFAULT ''",
            "ALTER TABLE sw_alerts ADD COLUMN fixed_version TEXT DEFAULT ''",
            "ALTER TABLE sw_alerts ADD COLUMN sources_json TEXT DEFAULT '[]'",
            "ALTER TABLE sw_alerts ADD COLUMN kev_due_date TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(col_def)
                conn.commit()
            except Exception:
                pass
    finally:
        conn.close()


# ── Settings & Webhook ────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    init_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM sw_settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def save_setting(key: str, value: str) -> None:
    init_db()
    conn = _connect()
    try:
        conn.execute("INSERT OR REPLACE INTO sw_settings (key, value) VALUES (?,?)", (key, value))
        conn.commit()
    finally:
        conn.close()


def notify_webhook(cve_id: str, software_name: str, environment: str, severity: str,
                   is_kev: bool, epss: float, fixed_version: str = "") -> None:
    url = get_setting("webhook_url", "")
    enabled = get_setting("webhook_enabled", "1")
    if not url or enabled != "1":
        return
    payload = {
        "title": f"\U0001f534 CVE Mới: {cve_id}",
        "message": (
            f"{severity} • {software_name} ({environment}) • EPSS: {epss*100:.0f}%"
            f"{' • KEV' if is_kev else ''}"
            f"{(' • Fix: ' + fixed_version) if fixed_version else ''}"
        ),
        "cve": cve_id, "software": software_name, "environment": environment,
        "severity": severity, "is_kev": is_kev, "epss": epss, "fixed_version": fixed_version,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    headers = {"Content-Type": "application/json"}
    if "ntfy.sh" in url:
        headers["Title"] = f"CVE Mới: {cve_id}"
        headers["Priority"] = "urgent" if severity == "CRITICAL" else "high"
    try:
        import ssl
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        ctx = None
        try:
            ctx = ssl.create_default_context()
            cafile = "/root/.ccr/ca-bundle.crt"
            if os.path.exists(cafile):
                ctx.load_verify_locations(cafile)
        except Exception:
            ctx = None
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            logger.info("Webhook sent for %s: %s", cve_id, resp.status)
    except Exception as exc:
        logger.warning("Webhook send failed for %s: %s", cve_id, exc)
        try:
            req2 = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req2, timeout=5) as resp2:
                logger.info("Webhook retry ok for %s: %s", cve_id, resp2.status)
        except Exception as exc2:
            logger.warning("Webhook retry failed: %s", exc2)


# ── Assets ────────────────────────────────────────────────────────────────────

def get_assets(search: str = "", environment: str = "") -> List[Dict]:
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT a.*, "
            "(SELECT COUNT(*) FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new') as new_alerts,"
            "(SELECT COUNT(*) FROM sw_alerts al WHERE al.asset_id=a.id) as total_alerts,"
            "(SELECT al.severity FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new' ORDER BY CASE al.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END LIMIT 1) as top_severity,"
            "(SELECT MAX(al.is_kev) FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new') as has_kev,"
            "(SELECT CAST(MIN(al.kev_due_date) AS TEXT) FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new' AND al.is_kev=1 AND al.kev_due_date!='') as nearest_kev_due,"
            "(SELECT CAST(ROUND(MIN(CAST((julianday(al.kev_due_date) - julianday('now')) AS REAL))) AS INTEGER) FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new' AND al.is_kev=1 AND al.kev_due_date!='') as kev_days_left,"
            "(SELECT CAST(ROUND(SUM(CASE al.severity WHEN 'CRITICAL' THEN al.epss*3 WHEN 'HIGH' THEN al.epss*2 WHEN 'MEDIUM' THEN al.epss ELSE al.epss*0.3 END * CASE WHEN al.is_kev=1 THEN 1.5 ELSE 1.0 END)*10) AS INTEGER) FROM sw_alerts al WHERE al.asset_id=a.id AND al.status='new') as risk_score "
            "FROM sw_assets a ORDER BY a.system_name, a.software_name"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if search:
                s = search.lower()
                if not any(s in str(d.get(f) or "").lower() for f in
                           ["system_name", "software_name", "vendor", "environment"]):
                    continue
            if environment:
                if environment.lower() not in (d.get("environment") or "").lower():
                    continue
            result.append(d)
        return result
    finally:
        conn.close()


def add_asset(system_name: str, environment: str, software_name: str,
              vendor: str, version: str, notes: str = "", cve_search_term: str = "") -> Dict:
    init_db()
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute(
            "INSERT INTO sw_assets (system_name, environment, software_name, vendor, version, "
            "cve_search_term, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (system_name.strip(), environment.strip(), software_name.strip(),
             vendor.strip(), version.strip(), cve_search_term.strip(), notes.strip(), now, now)
        )
        conn.commit()
        return {"ok": True, "id": cur.lastrowid}
    finally:
        conn.close()


def update_asset(asset_id: int, **kwargs) -> Dict:
    init_db()
    conn = _connect()
    allowed = {"system_name", "environment", "software_name", "vendor", "version",
               "cve_search_term", "notes", "enabled"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return {"ok": False, "reason": "Không có trường nào để cập nhật"}
    fields["updated_at"] = _now()
    sql = "UPDATE sw_assets SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
    try:
        cur = conn.execute(sql, list(fields.values()) + [asset_id])
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


def delete_asset(asset_id: int) -> Dict:
    init_db()
    conn = _connect()
    try:
        conn.execute("DELETE FROM sw_alerts WHERE asset_id=?", (asset_id,))
        cur = conn.execute("DELETE FROM sw_assets WHERE id=?", (asset_id,))
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


def import_csv(csv_text: str, replace: bool = False) -> Dict:
    """Import danh sách phần mềm từ CSV (hỗ trợ cả tiếng Việt và tiếng Anh)."""
    init_db()
    reader = csv.DictReader(io.StringIO(csv_text.strip()))
    headers = [h.strip() for h in (reader.fieldnames or [])]

    # Map cột theo tiếng Việt hoặc tiếng Anh
    col_map = {}
    vi_map = {
        "hệ thống thông tin thành phần": "system_name",
        "môi trường": "environment",
        "tên phần mềm": "software_name",
        "hãng cung cấp": "vendor",
        "phiên bản prod": "version",
        "phiên bản": "version",
        "phiên bản mới nhất": "latest_version",
        "tên tra cứu cve": "cve_search_term",
        "tên cvê": "cve_search_term",
        "ghi chú": "notes",
    }
    en_map = {
        "system name": "system_name",
        "environment": "environment",
        "software name": "software_name",
        "vendor": "vendor",
        "version": "version",
        "prod version": "version",
        "latest version": "latest_version",
        "cve search term": "cve_search_term",
        "search term": "cve_search_term",
        "notes": "notes",
    }
    for h in headers:
        norm = h.lower().strip()
        if norm in vi_map:
            col_map[h] = vi_map[norm]
        elif norm in en_map:
            col_map[h] = en_map[norm]

    if "software_name" not in col_map.values():
        return {"ok": False, "reason": "Không tìm thấy cột 'Tên phần mềm' hoặc 'Software Name'"}

    conn = _connect()
    try:
        if replace:
            conn.execute("DELETE FROM sw_alerts")
            conn.execute("DELETE FROM sw_assets")

        added = skipped = 0
        now = _now()
        for row in reader:
            mapped: Dict[str, str] = {}
            for orig_col, field in col_map.items():
                mapped[field] = str(row.get(orig_col) or "").strip()

            sw = mapped.get("software_name", "").strip()
            if not sw:
                skipped += 1
                continue

            # Bỏ qua dòng trùng (cùng software_name + vendor + version)
            vendor = mapped.get("vendor", "")
            version = mapped.get("version", "")
            existing = conn.execute(
                "SELECT id FROM sw_assets WHERE software_name=? AND vendor=? AND version=?",
                (sw, vendor, version)
            ).fetchone()
            if existing and not replace:
                skipped += 1
                continue

            conn.execute(
                "INSERT INTO sw_assets (system_name, environment, software_name, vendor, version, "
                "latest_version, cve_search_term, notes, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (mapped.get("system_name", ""), mapped.get("environment", ""),
                 sw, vendor, version, mapped.get("latest_version", ""),
                 mapped.get("cve_search_term", ""), mapped.get("notes", ""), now, now)
            )
            added += 1

        conn.commit()
        return {"ok": True, "added": added, "skipped": skipped}
    except Exception as exc:
        logger.error(f"CSV import error: {exc}")
        return {"ok": False, "reason": str(exc)}
    finally:
        conn.close()


def export_csv() -> str:
    """Xuất danh sách phần mềm ra CSV."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT system_name, environment, software_name, vendor, version, "
            "latest_version, notes FROM sw_assets ORDER BY system_name, software_name"
        ).fetchall()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(CSV_COLUMNS + ["Phiên bản mới nhất", "Trạng thái phiên bản", "Ghi chú"])
        for r in rows:
            cur_v = r["version"] or ""
            lat_v = r["latest_version"] or ""
            if not cur_v:
                ver_status = "CHƯA XÁC ĐỊNH"
            elif lat_v and cur_v != lat_v:
                ver_status = "CẦN NÂNG CẤP"
            elif lat_v and cur_v == lat_v:
                ver_status = "ÁP DỤNG"
            else:
                ver_status = "CHƯA XÁC ĐỊNH"
            writer.writerow([r["system_name"], r["environment"], r["software_name"],
                             r["vendor"], cur_v, lat_v, ver_status, r["notes"] or ""])
        return out.getvalue()
    finally:
        conn.close()


# ── Alerts ────────────────────────────────────────────────────────────────────

def get_alerts(asset_id: Optional[int] = None, status: str = "",
               severity: str = "", page: int = 1, per_page: int = 100) -> Dict:
    init_db()
    conn = _connect()
    try:
        clauses = []
        params: list = []
        if asset_id is not None:
            clauses.append("al.asset_id=?")
            params.append(asset_id)
        if status:
            clauses.append("al.status=?")
            params.append(status)
        if severity:
            clauses.append("al.severity=?")
            params.append(severity.upper())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        per_page = max(10, min(per_page, 500))
        page = max(1, page)
        offset = (page - 1) * per_page
        total = conn.execute(
            f"SELECT COUNT(*) FROM sw_alerts al JOIN sw_assets a ON a.id=al.asset_id {where}",
            params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT al.*, a.software_name, a.vendor, a.version as asset_version, "
            f"a.system_name, a.environment "
            f"FROM sw_alerts al JOIN sw_assets a ON a.id=al.asset_id "
            f"{where} ORDER BY al.is_kev DESC, al.epss DESC, al.created_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
        return {"alerts": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}
    finally:
        conn.close()


def ack_alert(alert_id: int) -> Dict:
    init_db()
    conn = _connect()
    try:
        cur = conn.execute("UPDATE sw_alerts SET status='acknowledged' WHERE id=?", (alert_id,))
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


def ack_all_alerts(asset_id: Optional[int] = None) -> Dict:
    init_db()
    conn = _connect()
    try:
        if asset_id:
            cur = conn.execute(
                "UPDATE sw_alerts SET status='acknowledged' WHERE asset_id=? AND status='new'",
                (asset_id,)
            )
        else:
            cur = conn.execute("UPDATE sw_alerts SET status='acknowledged' WHERE status='new'")
        conn.commit()
        return {"ok": True, "updated": cur.rowcount}
    finally:
        conn.close()


def delete_alert(alert_id: int) -> Dict:
    init_db()
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM sw_alerts WHERE id=?", (alert_id,))
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


# ── CVE Scanning ──────────────────────────────────────────────────────────────

def _normalize_name(name: str) -> str:
    """Chuẩn hóa tên để so sánh: bỏ version, parens, lowercase."""
    name = re.sub(r'\(.*?\)', '', name)
    name = re.sub(r'v?\d+[\.\d]*\+?$', '', name)
    return name.strip().lower()


def _name_tokens(name: str) -> List[str]:
    tokens = re.split(r'[\s/\-_]+', _normalize_name(name))
    return [t for t in tokens if len(t) >= 2]


def _matches_software(entry: Dict, sw_name: str, vendor: str) -> bool:
    """Kiểm tra CVE entry có liên quan đến phần mềm/vendor không."""
    sw_tokens = _name_tokens(sw_name)
    vendor_tokens = _name_tokens(vendor) if vendor else []

    # Collect text từ CVE entry
    text_parts = [
        entry.get("cve", ""),
        str(entry.get("title") or ""),
        str(entry.get("desc") or ""),
        str(entry.get("kev_vulnerability_name") or ""),
    ]
    for f in ["vendor", "product"]:
        v = entry.get(f)
        if isinstance(v, list):
            text_parts.extend(v)
        elif v:
            text_parts.append(str(v))

    text = " ".join(text_parts).lower()

    # Cần ít nhất 1 token của software_name match
    sw_match = sum(1 for t in sw_tokens if t in text)
    if sw_match == 0:
        return False

    # Nếu software name dài ≥ 2 tokens → cần match ít nhất 2
    if len(sw_tokens) >= 2 and sw_match < 2:
        # Fallback: check vendor match
        if vendor_tokens:
            vendor_match = sum(1 for t in vendor_tokens if t in text)
            if vendor_match == 0:
                return False
        else:
            return False

    return True


def _build_sources(cve_id: str, entry: dict, is_kev: bool) -> list:
    """Extract links đa nguồn từ pocindex entry."""
    sources = [{"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "type": "primary"}]
    if is_kev:
        sources.append({"name": "CISA KEV",
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "type": "advisory"})
    for url in (entry.get("poc") or []):
        if isinstance(url, str) and "github.com" in url:
            sources.append({"name": "GitHub PoC", "url": url, "type": "poc"})
            break
    for url in (entry.get("edb") or []):
        if isinstance(url, str):
            full = url if url.startswith("http") else f"https://www.exploit-db.com/exploits/{url}"
            sources.append({"name": "ExploitDB", "url": full, "type": "exploit"})
            break
    for url in (entry.get("nuclei") or []):
        if isinstance(url, str):
            sources.append({"name": "Nuclei", "url": url, "type": "template"})
            break
    for url in (entry.get("msf") or []):
        if isinstance(url, str):
            sources.append({"name": "Metasploit", "url": url, "type": "exploit"})
            break
    for url in (entry.get("vulhub") or []):
        if isinstance(url, str):
            sources.append({"name": "VulHub", "url": url, "type": "poc"})
            break
    try:
        import pocindex_mod as _pm
        advisories = (_pm.state.get("metadata") or {}).get(cve_id.upper(), {}).get("advisories") or []
        if isinstance(advisories, str):
            advisories = [advisories]
        for adv in advisories:
            if isinstance(adv, str) and "github.com/advisories" in adv:
                sources.append({"name": "GitHub Advisory", "url": adv, "type": "advisory"})
                break
    except Exception:
        pass
    return sources[:20]


def _fetch_osv_version_info(cve_id: str) -> Dict:
    """Fetch affected/fixed versions từ OSV.dev. Cache 7 ngày."""
    cve_up = cve_id.upper()
    conn = _connect()
    try:
        cached = conn.execute(
            "SELECT affected_v, fixed_v, fetched_at FROM sw_version_cache WHERE cve_id=?",
            (cve_up,)
        ).fetchone()
        if cached:
            try:
                fetched = datetime.fromisoformat(cached["fetched_at"].replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - fetched).days < 7:
                    return {"affected_versions": cached["affected_v"], "fixed_version": cached["fixed_v"]}
            except Exception:
                pass
    finally:
        conn.close()

    result: Dict = {"affected_versions": "", "fixed_version": ""}
    try:
        url = f"https://api.osv.dev/v1/vulns/{cve_up}"
        req = urllib.request.Request(url, headers={"User-Agent": "Metis-SoftwareWatch/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        fixed_versions: List[str] = []
        introduced_versions: List[str] = []
        for affected in (data.get("affected") or []):
            for rng in (affected.get("ranges") or []):
                for event in (rng.get("events") or []):
                    if "fixed" in event:
                        v = str(event["fixed"]).strip()
                        if v and v not in fixed_versions:
                            fixed_versions.append(v)
                    if "introduced" in event:
                        intro = str(event["introduced"]).strip()
                        if intro and intro != "0" and intro not in introduced_versions:
                            introduced_versions.append(intro)

        if fixed_versions:
            result["fixed_version"] = fixed_versions[-1]
            if introduced_versions:
                result["affected_versions"] = f">= {introduced_versions[0]}, < {fixed_versions[-1]}"
            else:
                result["affected_versions"] = f"< {fixed_versions[-1]}"
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            logger.debug(f"OSV.dev HTTP {exc.code} for {cve_up}")
    except Exception as exc:
        logger.debug(f"OSV.dev fetch {cve_up}: {exc}")

    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO sw_version_cache (cve_id, affected_v, fixed_v, fetched_at) "
            "VALUES (?, ?, ?, ?)",
            (cve_up, result["affected_versions"], result["fixed_version"], _now())
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

    return result


def _version_tuple(v: str) -> tuple:
    parts = re.findall(r'\d+', v.split("-")[0].split("+")[0])
    return tuple(int(p) for p in parts[:5]) if parts else (0,)


def _version_affected(asset_version: str, affected_range: str) -> bool:
    """True nếu asset_version nằm trong affected_range; fallback True nếu không parse được."""
    if not affected_range or not asset_version:
        return True
    try:
        av = _version_tuple(asset_version)
        for part in affected_range.split(","):
            part = part.strip()
            if part.startswith(">="):
                if av < _version_tuple(part[2:].strip()):
                    return False
            elif part.startswith(">"):
                if av <= _version_tuple(part[1:].strip()):
                    return False
            elif part.startswith("<="):
                if av > _version_tuple(part[2:].strip()):
                    return False
            elif part.startswith("<"):
                if av >= _version_tuple(part[1:].strip()):
                    return False
            elif part.startswith("="):
                if av != _version_tuple(part[1:].strip()):
                    return False
        return True
    except Exception:
        return True


def scan_asset(asset_id: int) -> Dict:
    """Quét CVE cho 1 asset, lưu alert nếu tìm thấy mới."""
    try:
        import pocindex_mod
    except ImportError:
        return {"ok": False, "reason": "pocindex_mod không khả dụng"}

    init_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM sw_assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            return {"ok": False, "reason": "Asset không tồn tại"}
        asset = dict(row)
    finally:
        conn.close()

    sw_name = asset["software_name"]
    vendor = asset["vendor"]
    cve_search_term = (asset.get("cve_search_term") or "").strip()

    # Tạo query tìm kiếm
    query_parts = []
    if cve_search_term:
        # Dùng tên tra cứu CVE do user nhập nếu có (ưu tiên hơn tên hiển thị)
        query_parts.append(cve_search_term)
    elif sw_name:
        # Lấy phần chính của tên (bỏ "(K8s)" dạng alias và phần trong ngoặc)
        clean = re.sub(r'\([^)]+\)', '', sw_name).strip()
        query_parts.append(clean)
    if vendor and not cve_search_term:
        # Lấy tên đầu tiên (trước dấu /)
        v = vendor.split("/")[0].strip()
        if v and v.lower() not in ["inc", "ltd", "corp", "foundation", "project"]:
            query_parts.append(v)

    found = 0
    all_entries = []

    for q in query_parts[:2]:  # Tối đa 2 query
        result = pocindex_mod.search_poc(q, limit=100)
        for e in result.get("results") or []:
            if _matches_software(e, sw_name, vendor):
                all_entries.append(e)

    # Dedup by CVE
    seen_cves = set()
    deduped = []
    for e in all_entries:
        cve = str(e.get("cve") or "").upper()
        if cve and cve not in seen_cves:
            seen_cves.add(cve)
            deduped.append(e)

    asset_version = asset.get("version", "").strip()
    latest_fix_versions: List[str] = []

    conn = _connect()
    try:
        now = _now()
        for e in deduped:
            cve = str(e.get("cve") or "").upper()
            if not cve:
                continue

            epss_meta = (pocindex_mod.state.get("epss") or {}).get(cve) or []
            epss = float(epss_meta[0]) if epss_meta else 0.0
            kev_data = pocindex_mod.state.get("kev") or {}
            kev_entry = kev_data.get(cve, {})
            is_kev = 1 if kev_entry else 0
            kev_due_date = kev_entry.get("due_date", "") if isinstance(kev_entry, dict) else ""
            severity = str(e.get("severity") or "")
            title = str(e.get("title") or e.get("kev_vulnerability_name") or cve)
            poc_count = len(e.get("_allLinks") or [])
            published = str(e.get("kev_date_added") or e.get("published") or "")

            # Fetch OSV cho TẤT CẢ CVE (không gate theo asset_version)
            osv = _fetch_osv_version_info(cve)
            affected_versions = osv.get("affected_versions", "")
            fixed_version = osv.get("fixed_version", "")

            # Chỉ filter version khi asset CÓ version VÀ OSV có affected range
            if asset_version and affected_versions:
                if not _version_affected(asset_version, affected_versions):
                    continue  # CVE không ảnh hưởng phiên bản đang dùng

            sources = _build_sources(cve, e, bool(is_kev))
            sources_json = json.dumps(sources, ensure_ascii=False)

            if fixed_version:
                latest_fix_versions.append(fixed_version)

            try:
                conn.execute(
                    "INSERT OR IGNORE INTO sw_alerts "
                    "(asset_id, cve_id, title, severity, epss, is_kev, poc_count, published, source, "
                    "affected_versions, fixed_version, sources_json, kev_due_date, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)",
                    (asset_id, cve, title, severity, epss, is_kev, poc_count, published, "pocindex/kev",
                     affected_versions, fixed_version, sources_json, kev_due_date, now)
                )
                new_row = conn.execute("SELECT changes()").fetchone()[0] > 0
                if new_row:
                    found += 1
                    if severity in ("CRITICAL", "HIGH") and (is_kev or epss >= 0.5):
                        try:
                            notify_webhook(cve, sw_name, asset.get("environment", ""),
                                           severity, bool(is_kev), epss, fixed_version)
                        except Exception:
                            pass
                else:
                    # Upsert: refresh fixed_version và sources khi có data tốt hơn
                    has_better_sources = len(sources) > 1
                    if fixed_version or has_better_sources or kev_due_date:
                        conn.execute(
                            """UPDATE sw_alerts SET fixed_version=?, sources_json=?, affected_versions=?, kev_due_date=?
                               WHERE asset_id=? AND cve_id=? AND (
                                   (fixed_version='' AND ?) OR
                                   (sources_json='[]' OR sources_json LIKE '[{"name": "NVD"%') AND ? OR
                                   (kev_due_date='' AND ?)
                               )""",
                            (fixed_version, sources_json, affected_versions, kev_due_date,
                             asset_id, cve, bool(fixed_version), has_better_sources, bool(kev_due_date))
                        )
            except sqlite3.IntegrityError:
                pass

        conn.commit()

        if latest_fix_versions:
            try:
                latest = max(latest_fix_versions, key=_version_tuple)
            except Exception:
                latest = latest_fix_versions[-1]
            conn.execute(
                "UPDATE sw_assets SET latest_version=?, version_checked_at=? WHERE id=?",
                (latest, _now(), asset_id)
            )
            conn.commit()
    finally:
        conn.close()

    return {"ok": True, "asset_id": asset_id, "new_alerts": found, "total_matched": len(deduped)}


def scan_all() -> Dict:
    """Quét tất cả assets đang enabled."""
    init_db()
    conn = _connect()
    try:
        assets = conn.execute("SELECT id FROM sw_assets WHERE enabled=1").fetchall()
    finally:
        conn.close()

    total_new = 0
    errors = []
    for a in assets:
        try:
            res = scan_asset(a["id"])
            total_new += res.get("new_alerts", 0)
        except Exception as exc:
            errors.append({"asset_id": a["id"], "error": str(exc)})

    return {
        "ok": True,
        "scanned": len(assets),
        "new_alerts": total_new,
        "errors": errors,
    }


def export_alerts_csv(asset_id: Optional[int] = None, status: str = "",
                      severity: str = "", environment: str = "",
                      asset_ids: str = "") -> str:
    """Xuất cảnh báo CVE ra CSV."""
    init_db()
    conn = _connect()
    try:
        clauses = []
        params: list = []
        if asset_id is not None:
            clauses.append("al.asset_id=?")
            params.append(asset_id)
        if asset_ids:
            id_list = [i.strip() for i in asset_ids.split(",") if i.strip().isdigit()]
            if id_list:
                clauses.append(f"al.asset_id IN ({','.join(['?']*len(id_list))})")
                params.extend(id_list)
        if status:
            clauses.append("al.status=?")
            params.append(status)
        if severity:
            clauses.append("al.severity=?")
            params.append(severity.upper())
        if environment:
            clauses.append("a.environment=?")
            params.append(environment)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT al.*, a.software_name, a.vendor, a.version as asset_version, "
            f"a.system_name, a.environment "
            f"FROM sw_alerts al JOIN sw_assets a ON a.id=al.asset_id "
            f"{where} ORDER BY a.software_name, al.is_kev DESC, al.epss DESC, al.created_at DESC",
            params
        ).fetchall()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "Phần mềm", "Hãng cung cấp", "Phiên bản hiện tại", "Phiên bản vá", "Hệ thống", "Môi trường",
            "CVE", "Tiêu đề", "Mức độ", "EPSS (%)", "Trong KEV",
            "Số PoC", "Ngày phát hiện", "Trạng thái",
            "Link NVD", "Link GitHub PoC", "Link ExploitDB", "Link Nuclei", "Link Metasploit", "Link VulHub"
        ])
        for r in rows:
            epss_pct = f"{float(r['epss'] or 0) * 100:.1f}%" if r['epss'] else "0.0%"
            sources: list = []
            try:
                sources = json.loads(r["sources_json"] or "[]")
            except Exception:
                pass

            def _src_link(name_prefix: str) -> str:
                for s in sources:
                    if str(s.get("name", "")).startswith(name_prefix):
                        return s.get("url", "")
                return ""

            writer.writerow([
                r["software_name"], r["vendor"] or "", r["asset_version"] or "",
                r["fixed_version"] or "", r["system_name"], r["environment"],
                r["cve_id"], r["title"] or "", r["severity"] or "",
                epss_pct, "Có" if r["is_kev"] else "Không",
                r["poc_count"] or 0, r["published"] or "",
                "Mới" if r["status"] == "new" else "Đã xem",
                _src_link("NVD") or (f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}" if r["cve_id"] else ""),
                _src_link("GitHub PoC"),
                _src_link("ExploitDB"),
                _src_link("Nuclei"),
                _src_link("Metasploit"),
                _src_link("VulHub"),
            ])
        return out.getvalue()
    finally:
        conn.close()


# ── Libraries ─────────────────────────────────────────────────────────────────

def get_libraries(search: str = "", system_name: str = "",
                  status: str = "") -> List[Dict]:
    init_db()
    conn = _connect()
    try:
        clauses = []
        params: list = []
        if system_name:
            clauses.append("system_name=?")
            params.append(system_name)
        if status:
            clauses.append("status=?")
            params.append(status.upper())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM sw_libraries {where} ORDER BY system_name, library_name",
            params
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if search:
                s = search.lower()
                if not any(s in str(d.get(f) or "").lower()
                           for f in ["library_name", "system_name", "stack", "notes"]):
                    continue
            result.append(d)
        return result
    finally:
        conn.close()


def add_library(system_name: str, library_name: str, stack: str = "",
                min_version: str = "", current_version: str = "",
                status: str = "APPROVED", notes: str = "") -> Dict:
    init_db()
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute(
            "INSERT INTO sw_libraries (system_name, library_name, stack, min_version, "
            "current_version, status, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (system_name.strip(), library_name.strip(), stack.strip(),
             min_version.strip(), current_version.strip(),
             status.upper().strip() or "APPROVED", notes.strip(), now, now)
        )
        conn.commit()
        return {"ok": True, "id": cur.lastrowid}
    finally:
        conn.close()


def update_library(lib_id: int, **kwargs) -> Dict:
    init_db()
    conn = _connect()
    allowed = {"system_name", "library_name", "stack", "min_version",
               "current_version", "status", "notes"}
    fields = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if "status" in fields:
        fields["status"] = str(fields["status"]).upper()
    if not fields:
        return {"ok": False, "reason": "Không có trường nào để cập nhật"}
    fields["updated_at"] = _now()
    sql = "UPDATE sw_libraries SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?"
    try:
        cur = conn.execute(sql, list(fields.values()) + [lib_id])
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


def delete_library(lib_id: int) -> Dict:
    init_db()
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM sw_libraries WHERE id=?", (lib_id,))
        conn.commit()
        return {"ok": cur.rowcount > 0}
    finally:
        conn.close()


def import_libraries_csv(csv_text: str) -> Dict:
    """Import danh sách thư viện từ CSV."""
    init_db()
    reader = csv.DictReader(io.StringIO(csv_text.strip()))
    headers = [h.strip() for h in (reader.fieldnames or [])]

    col_map = {}
    vi_map = {
        "thư viện / package": "library_name",
        "thư viện/package": "library_name",
        "thư viện": "library_name",
        "package": "library_name",
        "hệ thống": "system_name",
        "hệ thống thông tin thành phần": "system_name",
        "stack": "stack",
        "version được phép (tối thiểu)": "min_version",
        "version tối thiểu": "min_version",
        "phiên bản tối thiểu": "min_version",
        "phiên bản hiện tại": "current_version",
        "version hiện tại": "current_version",
        "trạng thái": "status",
        "ghi chú": "notes",
    }
    en_map = {
        "library": "library_name",
        "library name": "library_name",
        "package name": "library_name",
        "system name": "system_name",
        "system": "system_name",
        "stack": "stack",
        "min version": "min_version",
        "minimum version": "min_version",
        "current version": "current_version",
        "status": "status",
        "notes": "notes",
    }
    for h in headers:
        norm = h.lower().strip()
        if norm in vi_map:
            col_map[h] = vi_map[norm]
        elif norm in en_map:
            col_map[h] = en_map[norm]

    if "library_name" not in col_map.values():
        return {"ok": False, "reason": "Không tìm thấy cột 'Thư viện / Package' hoặc 'Library Name'"}

    conn = _connect()
    try:
        added = skipped = 0
        now = _now()
        for row in reader:
            mapped: Dict[str, str] = {}
            for orig_col, field in col_map.items():
                mapped[field] = str(row.get(orig_col) or "").strip()

            lib = mapped.get("library_name", "").strip()
            if not lib:
                skipped += 1
                continue

            existing = conn.execute(
                "SELECT id FROM sw_libraries WHERE library_name=? AND system_name=?",
                (lib, mapped.get("system_name", ""))
            ).fetchone()
            if existing:
                skipped += 1
                continue

            st = (mapped.get("status") or "APPROVED").upper()
            if st not in ("APPROVED", "REVIEW", "BLOCKED"):
                st = "APPROVED"

            conn.execute(
                "INSERT INTO sw_libraries (system_name, library_name, stack, min_version, "
                "current_version, status, notes, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (mapped.get("system_name", ""), lib,
                 mapped.get("stack", ""), mapped.get("min_version", ""),
                 mapped.get("current_version", ""), st,
                 mapped.get("notes", ""), now, now)
            )
            added += 1

        conn.commit()
        return {"ok": True, "added": added, "skipped": skipped}
    except Exception as exc:
        logger.error(f"Libraries CSV import error: {exc}")
        return {"ok": False, "reason": str(exc)}
    finally:
        conn.close()


def export_libraries_csv() -> str:
    """Xuất danh sách thư viện ra CSV."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT system_name, library_name, stack, min_version, current_version, status, notes "
            "FROM sw_libraries ORDER BY system_name, library_name"
        ).fetchall()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "Hệ thống", "Thư viện / Package", "Stack",
            "Version tối thiểu", "Phiên bản hiện tại", "Trạng thái", "Ghi chú"
        ])
        for r in rows:
            writer.writerow([
                r["system_name"], r["library_name"], r["stack"],
                r["min_version"] or "", r["current_version"] or "",
                r["status"], r["notes"] or ""
            ])
        return out.getvalue()
    finally:
        conn.close()


def get_summary() -> Dict:
    """Thống kê tổng quan."""
    init_db()
    conn = _connect()
    try:
        total_assets = conn.execute("SELECT COUNT(*) FROM sw_assets WHERE enabled=1").fetchone()[0]
        new_alerts = conn.execute("SELECT COUNT(*) FROM sw_alerts WHERE status='new'").fetchone()[0]
        kev_alerts = conn.execute(
            "SELECT COUNT(*) FROM sw_alerts WHERE status='new' AND is_kev=1"
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM sw_alerts WHERE status='new' AND severity IN ('CRITICAL','HIGH')"
        ).fetchone()[0]
        return {
            "total_assets": total_assets,
            "new_alerts": new_alerts,
            "kev_alerts": kev_alerts,
            "critical_alerts": critical,
        }
    finally:
        conn.close()
