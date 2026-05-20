"""
Couche d'accès SQLite.
Toutes les requêtes SQL sont ici ; le reste du code utilise uniquement ce module.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Optional

from app import config
from app.logger import log
from app.models import CyberItem, Severity


#  Connexion 

@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


#  Initialisation du schéma 

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    url         TEXT,
    last_check  TIMESTAMP,
    item_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_hash              TEXT UNIQUE NOT NULL,
    source                  TEXT NOT NULL,
    external_id             TEXT DEFAULT '',
    title                   TEXT NOT NULL,
    url                     TEXT DEFAULT '',
    summary                 TEXT DEFAULT '',
    published_at            TIMESTAMP,
    fetched_at              TIMESTAMP NOT NULL,
    item_type               TEXT NOT NULL DEFAULT 'NEWS',
    severity                TEXT NOT NULL DEFAULT 'INFO',
    cvss_score              REAL,
    cvss_version            TEXT,
    internal_score          REAL DEFAULT 0.0,
    vendor                  TEXT DEFAULT '',
    product                 TEXT DEFAULT '',
    tags                    TEXT DEFAULT '[]',
    is_kev                  INTEGER DEFAULT 0,
    is_actively_exploited   INTEGER DEFAULT 0,
    has_public_exploit      INTEGER DEFAULT 0,
    is_rce                  INTEGER DEFAULT 0,
    is_auth_bypass          INTEGER DEFAULT 0,
    is_privilege_escalation INTEGER DEFAULT 0,
    mentions_ransomware     INTEGER DEFAULT 0,
    patch_available         INTEGER DEFAULT 0,
    extra_urls              TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_items_dedup      ON items(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_items_published  ON items(published_at);
CREATE INDEX IF NOT EXISTS idx_items_severity   ON items(severity);
CREATE INDEX IF NOT EXISTS idx_items_type       ON items(item_type);
CREATE INDEX IF NOT EXISTS idx_items_source     ON items(source);

CREATE TABLE IF NOT EXISTS alerts_sent (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     INTEGER NOT NULL REFERENCES items(id),
    sent_at     TIMESTAMP NOT NULL,
    chat_id     TEXT NOT NULL,
    message_id  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_alerts_item ON alerts_sent(item_id);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    new_items   INTEGER DEFAULT 0,
    alerts_sent INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    mode        TEXT DEFAULT 'scheduled'
);

CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    updated TIMESTAMP NOT NULL
);
"""


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    log.info("Base de données initialisée : %s", config.DB_PATH)


#  Sources 

def upsert_source(name: str, url: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sources(name, url) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET url=excluded.url",
            (name, url),
        )


def touch_source(name: str, item_count: int = 0) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE sources SET last_check=?, item_count=item_count+? WHERE name=?",
            (datetime.utcnow(), item_count, name),
        )


#  Items 

def item_exists(dedup_hash: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM items WHERE dedup_hash=?", (dedup_hash,)
        ).fetchone()
    return row is not None


def insert_item(item: CyberItem) -> Optional[int]:
    """Insère un item. Retourne l'id ou None si déjà existant."""
    if item_exists(item.dedup_hash):
        return None

    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO items(
                dedup_hash, source, external_id, title, url, summary,
                published_at, fetched_at, item_type, severity,
                cvss_score, cvss_version, internal_score,
                vendor, product, tags,
                is_kev, is_actively_exploited, has_public_exploit,
                is_rce, is_auth_bypass, is_privilege_escalation,
                mentions_ransomware, patch_available, extra_urls
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item.dedup_hash,
                item.source,
                item.external_id,
                item.title,
                item.url,
                item.summary,
                item.published_at,
                item.fetched_at,
                item.item_type,
                item.severity,
                item.cvss_score,
                item.cvss_version,
                item.internal_score,
                item.vendor,
                item.product,
                json.dumps(item.tags, ensure_ascii=False),
                int(item.is_kev),
                int(item.is_actively_exploited),
                int(item.has_public_exploit),
                int(item.is_rce),
                int(item.is_auth_bypass),
                int(item.is_privilege_escalation),
                int(item.mentions_ransomware),
                int(item.patch_available),
                json.dumps(item.extra_urls, ensure_ascii=False),
            ),
        )
        return cur.lastrowid


def mark_alert_sent(item_id: int, chat_id: str, message_id: Optional[int] = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts_sent(item_id, sent_at, chat_id, message_id) VALUES(?,?,?,?)",
            (item_id, datetime.utcnow(), chat_id, message_id),
        )


def alert_already_sent(item_id: int, chat_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM alerts_sent WHERE item_id=? AND chat_id=?",
            (item_id, chat_id),
        ).fetchone()
    return row is not None


def get_items_since(since: datetime, severity: Optional[str] = None) -> list[sqlite3.Row]:
    query = "SELECT * FROM items WHERE fetched_at >= ?"
    params: list = [since]
    if severity:
        query += " AND severity=?"
        params.append(severity)
    query += " ORDER BY internal_score DESC, published_at DESC"
    with get_conn() as conn:
        return conn.execute(query, params).fetchall()


def get_unsent_alerts(chat_id: str, min_severity: str = "HIGH") -> list[sqlite3.Row]:
    severities = {
        "CRITICAL": ["CRITICAL"],
        "HIGH":     ["CRITICAL", "HIGH"],
        "MEDIUM":   ["CRITICAL", "HIGH", "MEDIUM"],
        "INFO":     ["CRITICAL", "HIGH", "MEDIUM", "INFO"],
    }
    allowed = severities.get(min_severity, ["CRITICAL", "HIGH"])
    placeholders = ",".join("?" * len(allowed))
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT i.* FROM items i
            WHERE i.severity IN ({placeholders})
              AND i.id NOT IN (
                  SELECT item_id FROM alerts_sent WHERE chat_id=?
              )
            ORDER BY i.internal_score DESC, i.published_at DESC
            """,
            (*allowed, chat_id),
        ).fetchall()


def get_stats_since(since: datetime) -> dict:
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=?", (since,)
        ).fetchone()[0]
        by_severity = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT severity, COUNT(*) FROM items WHERE fetched_at>=? GROUP BY severity",
                (since,),
            ).fetchall()
        }
        by_type = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT item_type, COUNT(*) FROM items WHERE fetched_at>=? GROUP BY item_type",
                (since,),
            ).fetchall()
        }
        kev_count = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND is_kev=1", (since,)
        ).fetchone()[0]
        exploit_count = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND has_public_exploit=1",
            (since,),
        ).fetchone()[0]
    return {
        "total": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "kev_count": kev_count,
        "exploit_count": exploit_count,
    }


#  Settings 

def set_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO settings(key, value, updated) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
            (key, value, datetime.utcnow()),
        )


def get_setting(key: str, default: str = "") -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


#  Runs 

def start_run(mode: str = "scheduled") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO runs(started_at, mode) VALUES(?,?)",
            (datetime.utcnow(), mode),
        )
        return cur.lastrowid


def finish_run(run_id: int, new_items: int, alerts_sent: int, errors: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE runs SET finished_at=?, new_items=?, alerts_sent=?, errors=? WHERE id=?",
            (datetime.utcnow(), new_items, alerts_sent, errors, run_id),
        )
