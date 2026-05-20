"""
Couche d'accès SQLite v2.
Nouvelles tables : alert_queue, mute, watchlist_hits.
FTS5 pour la recherche plein texte.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Generator, Optional

from app import config
from app.logger import log
from app.models import CyberItem


#  Connexion 

@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


#  Schéma 

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    url         TEXT DEFAULT '',
    last_check  TIMESTAMP,
    item_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_hash              TEXT UNIQUE NOT NULL,
    source                  TEXT NOT NULL,
    source_names            TEXT DEFAULT '[]',
    external_id             TEXT DEFAULT '',
    title                   TEXT NOT NULL,
    url                     TEXT DEFAULT '',
    summary                 TEXT DEFAULT '',
    published_at            TIMESTAMP,
    fetched_at              TIMESTAMP NOT NULL,
    item_type               TEXT NOT NULL DEFAULT 'NEWS',
    severity                TEXT NOT NULL DEFAULT 'INFO',

    cvss_score              REAL,
    cvss_version            TEXT DEFAULT '',
    cvss_vector             TEXT DEFAULT '',
    epss_score              REAL,
    epss_percentile         REAL,
    internal_score          REAL DEFAULT 0.0,

    vendor                  TEXT DEFAULT '',
    product                 TEXT DEFAULT '',
    affected_versions       TEXT DEFAULT '',
    fixed_versions          TEXT DEFAULT '',
    tags                    TEXT DEFAULT '[]',

    is_kev                  INTEGER DEFAULT 0,
    is_actively_exploited   INTEGER DEFAULT 0,
    has_public_exploit      INTEGER DEFAULT 0,
    is_rce                  INTEGER DEFAULT 0,
    is_auth_bypass          INTEGER DEFAULT 0,
    is_privilege_escalation INTEGER DEFAULT 0,
    is_sqli                 INTEGER DEFAULT 0,
    is_ssrf                 INTEGER DEFAULT 0,
    is_xxe                  INTEGER DEFAULT 0,
    mentions_ransomware     INTEGER DEFAULT 0,
    patch_available         INTEGER DEFAULT 0,
    workaround_available    INTEGER DEFAULT 0,
    internet_exposed        INTEGER DEFAULT 0,
    on_watchlist            INTEGER DEFAULT 0,
    enriched                INTEGER DEFAULT 0,

    extra_urls              TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_items_dedup      ON items(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_items_published  ON items(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_fetched    ON items(fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_severity   ON items(severity);
CREATE INDEX IF NOT EXISTS idx_items_type       ON items(item_type);
CREATE INDEX IF NOT EXISTS idx_items_ext_id     ON items(external_id);
CREATE INDEX IF NOT EXISTS idx_items_score      ON items(internal_score DESC);
CREATE INDEX IF NOT EXISTS idx_items_kev        ON items(is_kev);
CREATE INDEX IF NOT EXISTS idx_items_watchlist  ON items(on_watchlist);

-- FTS5 pour recherche plein texte
CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5(
    title,
    summary,
    external_id,
    vendor,
    product,
    content='items',
    content_rowid='id',
    tokenize='unicode61'
);

-- Triggers pour maintenir l'index FTS5
CREATE TRIGGER IF NOT EXISTS items_fts_insert AFTER INSERT ON items BEGIN
    INSERT INTO items_fts(rowid, title, summary, external_id, vendor, product)
    VALUES (new.id, new.title, new.summary, new.external_id, new.vendor, new.product);
END;
CREATE TRIGGER IF NOT EXISTS items_fts_delete AFTER DELETE ON items BEGIN
    INSERT INTO items_fts(items_fts, rowid, title, summary, external_id, vendor, product)
    VALUES ('delete', old.id, old.title, old.summary, old.external_id, old.vendor, old.product);
END;
CREATE TRIGGER IF NOT EXISTS items_fts_update AFTER UPDATE ON items BEGIN
    INSERT INTO items_fts(items_fts, rowid, title, summary, external_id, vendor, product)
    VALUES ('delete', old.id, old.title, old.summary, old.external_id, old.vendor, old.product);
    INSERT INTO items_fts(rowid, title, summary, external_id, vendor, product)
    VALUES (new.id, new.title, new.summary, new.external_id, new.vendor, new.product);
END;

-- Queue des alertes à envoyer (persistante)
CREATE TABLE IF NOT EXISTS alert_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     INTEGER NOT NULL REFERENCES items(id),
    chat_id     TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 5,  -- 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=INFO
    queued_at   TIMESTAMP NOT NULL,
    send_after  TIMESTAMP NOT NULL,
    attempts    INTEGER DEFAULT 0,
    sent        INTEGER DEFAULT 0,
    sent_at     TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_queue_pending ON alert_queue(sent, send_after, priority);

-- Alertes effectivement envoyées (historique)
CREATE TABLE IF NOT EXISTS alerts_sent (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     INTEGER NOT NULL REFERENCES items(id),
    sent_at     TIMESTAMP NOT NULL,
    chat_id     TEXT NOT NULL,
    message_id  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_item ON alerts_sent(item_id, chat_id);

-- Mute Telegram (silence temporaire des alertes)
CREATE TABLE IF NOT EXISTS mute (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id     TEXT NOT NULL,
    muted_at    TIMESTAMP NOT NULL,
    mute_until  TIMESTAMP NOT NULL,
    reason      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mute_chat ON mute(chat_id, mute_until);

-- Historique des runs
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TIMESTAMP NOT NULL,
    finished_at  TIMESTAMP,
    new_items    INTEGER DEFAULT 0,
    enriched     INTEGER DEFAULT 0,
    alerts_sent  INTEGER DEFAULT 0,
    errors       INTEGER DEFAULT 0,
    mode         TEXT DEFAULT 'scheduled'
);

-- Paramètres persistants (offset Telegram, settings)
CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    updated TIMESTAMP NOT NULL
);
"""


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    log.info("Base de données v2 initialisée : %s", config.DB_PATH)


#  Sources 

def upsert_source(name: str, url: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sources(name,url) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET url=excluded.url",
            (name, url),
        )

def touch_source(name: str, count: int = 0) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE sources SET last_check=?, item_count=item_count+? WHERE name=?",
            (datetime.utcnow(), count, name),
        )


#  Items 

def item_exists(dedup_hash: str) -> bool:
    with get_conn() as conn:
        return conn.execute(
            "SELECT 1 FROM items WHERE dedup_hash=?", (dedup_hash,)
        ).fetchone() is not None


def get_item_by_cve(cve_id: str) -> Optional[sqlite3.Row]:
    """Trouve un item existant par son CVE ID (cross-source dedup)."""
    if not cve_id:
        return None
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM items WHERE external_id=? ORDER BY internal_score DESC LIMIT 1",
            (cve_id.upper(),),
        ).fetchone()


def insert_item(item: CyberItem) -> Optional[int]:
    """Insère un item. Retourne l'id ou None si déjà existant (par hash)."""
    if item_exists(item.dedup_hash):
        return None
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO items(
                dedup_hash, source, source_names, external_id,
                title, url, summary, published_at, fetched_at,
                item_type, severity,
                cvss_score, cvss_version, cvss_vector,
                epss_score, epss_percentile, internal_score,
                vendor, product, affected_versions, fixed_versions, tags,
                is_kev, is_actively_exploited, has_public_exploit,
                is_rce, is_auth_bypass, is_privilege_escalation,
                is_sqli, is_ssrf, is_xxe,
                mentions_ransomware, patch_available, workaround_available,
                internet_exposed, on_watchlist, enriched,
                extra_urls
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item.dedup_hash,
                item.source,
                json.dumps(item.source_names or [item.source]),
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
                item.cvss_vector,
                item.epss_score,
                item.epss_percentile,
                item.internal_score,
                item.vendor,
                item.product,
                item.affected_versions,
                item.fixed_versions,
                json.dumps(item.tags),
                int(item.is_kev),
                int(item.is_actively_exploited),
                int(item.has_public_exploit),
                int(item.is_rce),
                int(item.is_auth_bypass),
                int(item.is_privilege_escalation),
                int(item.is_sqli),
                int(item.is_ssrf),
                int(item.is_xxe),
                int(item.mentions_ransomware),
                int(item.patch_available),
                int(item.workaround_available),
                int(item.internet_exposed),
                int(item.on_watchlist),
                int(item.enriched),
                json.dumps(item.extra_urls),
            ),
        )
        return cur.lastrowid


def update_item_enrichment(item_id: int, item: CyberItem) -> None:
    """Met à jour les champs d'enrichissement d'un item existant."""
    with get_conn() as conn:
        conn.execute(
            """UPDATE items SET
               cvss_score=?, cvss_version=?, cvss_vector=?,
               epss_score=?, epss_percentile=?,
               internal_score=?, severity=?,
               vendor=CASE WHEN vendor='' THEN ? ELSE vendor END,
               product=CASE WHEN product='' THEN ? ELSE product END,
               affected_versions=?, fixed_versions=?,
               is_rce=MAX(is_rce,?), is_auth_bypass=MAX(is_auth_bypass,?),
               is_privilege_escalation=MAX(is_privilege_escalation,?),
               is_actively_exploited=MAX(is_actively_exploited,?),
               has_public_exploit=MAX(has_public_exploit,?),
               patch_available=MAX(patch_available,?),
               on_watchlist=MAX(on_watchlist,?),
               enriched=1
            WHERE id=?""",
            (
                item.cvss_score, item.cvss_version, item.cvss_vector,
                item.epss_score, item.epss_percentile,
                item.internal_score, item.severity,
                item.vendor, item.product,
                item.affected_versions, item.fixed_versions,
                int(item.is_rce), int(item.is_auth_bypass),
                int(item.is_privilege_escalation),
                int(item.is_actively_exploited),
                int(item.has_public_exploit),
                int(item.patch_available),
                int(item.on_watchlist),
                item_id,
            ),
        )


def merge_source_into_item(item_id: int, source_name: str, extra_url: str = "") -> None:
    """Ajoute une source supplémentaire à un item existant (cross-source merge)."""
    with get_conn() as conn:
        row = conn.execute("SELECT source_names, extra_urls FROM items WHERE id=?", (item_id,)).fetchone()
        if not row:
            return
        names = json.loads(row["source_names"] or "[]")
        if source_name not in names:
            names.append(source_name)
        urls = json.loads(row["extra_urls"] or "[]")
        if extra_url and extra_url not in urls:
            urls.append(extra_url)
        conn.execute(
            "UPDATE items SET source_names=?, extra_urls=? WHERE id=?",
            (json.dumps(names), json.dumps(urls), item_id),
        )


#  FTS5 Search 

def search_items(query: str, limit: int = 10) -> list[sqlite3.Row]:
    """Recherche plein texte via FTS5."""
    with get_conn() as conn:
        try:
            return conn.execute(
                """SELECT i.* FROM items i
                   JOIN items_fts fts ON i.id = fts.rowid
                   WHERE items_fts MATCH ?
                   ORDER BY rank, i.internal_score DESC
                   LIMIT ?""",
                (query, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            # Fallback LIKE si FTS échoue
            like = f"%{query}%"
            return conn.execute(
                "SELECT * FROM items WHERE title LIKE ? OR summary LIKE ? OR external_id LIKE ? LIMIT ?",
                (like, like, like, limit),
            ).fetchall()


#  Alert Queue 

_PRIORITY_MAP = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "INFO": 4}


def enqueue_alert(
    item_id: int,
    chat_id: str,
    severity: str,
    send_after: Optional[datetime] = None,
) -> None:
    """Ajoute une alerte dans la queue persistante."""
    if not chat_id:
        return
    priority = _PRIORITY_MAP.get(severity, 4)
    if send_after is None:
        send_after = datetime.utcnow()
    with get_conn() as conn:
        # Éviter les doublons dans la queue
        existing = conn.execute(
            "SELECT 1 FROM alert_queue WHERE item_id=? AND chat_id=? AND sent=0",
            (item_id, chat_id),
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO alert_queue(item_id,chat_id,priority,queued_at,send_after) VALUES(?,?,?,?,?)",
                (item_id, chat_id, priority, datetime.utcnow(), send_after),
            )


def get_pending_alerts(chat_id: str, limit: int = 20) -> list[sqlite3.Row]:
    """Retourne les alertes en attente, triées par priorité puis date."""
    now = datetime.utcnow()
    with get_conn() as conn:
        return conn.execute(
            """SELECT q.id as queue_id, q.item_id, q.priority, q.attempts,
                      i.*
               FROM alert_queue q
               JOIN items i ON q.item_id = i.id
               WHERE q.chat_id=? AND q.sent=0 AND q.send_after<=?
               ORDER BY q.priority ASC, q.queued_at ASC
               LIMIT ?""",
            (chat_id, now, limit),
        ).fetchall()


def mark_queue_sent(queue_id: int, message_id: Optional[int] = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE alert_queue SET sent=1, sent_at=?, attempts=attempts+1 WHERE id=?",
            (datetime.utcnow(), queue_id),
        )


def increment_queue_attempt(queue_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE alert_queue SET attempts=attempts+1 WHERE id=?",
            (queue_id,),
        )


def alert_already_sent(item_id: int, chat_id: str) -> bool:
    with get_conn() as conn:
        return conn.execute(
            "SELECT 1 FROM alerts_sent WHERE item_id=? AND chat_id=?",
            (item_id, chat_id),
        ).fetchone() is not None


def mark_alert_sent(item_id: int, chat_id: str, message_id: Optional[int] = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts_sent(item_id,sent_at,chat_id,message_id) VALUES(?,?,?,?)",
            (item_id, datetime.utcnow(), chat_id, message_id),
        )


#  Mute 

def mute_chat(chat_id: str, minutes: int, reason: str = "") -> None:
    until = datetime.utcnow() + timedelta(minutes=minutes)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO mute(chat_id,muted_at,mute_until,reason) VALUES(?,?,?,?)",
            (chat_id, datetime.utcnow(), until, reason),
        )
    log.info("Mute activé pour %s jusqu'à %s", chat_id, until.strftime("%H:%M"))


def unmute_chat(chat_id: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE mute SET mute_until=? WHERE chat_id=? AND mute_until>?",
            (datetime.utcnow(), chat_id, datetime.utcnow()),
        )


def is_muted(chat_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM mute WHERE chat_id=? AND mute_until>? ORDER BY mute_until DESC LIMIT 1",
            (chat_id, datetime.utcnow()),
        ).fetchone()
    return row is not None


def mute_until(chat_id: str) -> Optional[datetime]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT mute_until FROM mute WHERE chat_id=? AND mute_until>? ORDER BY mute_until DESC LIMIT 1",
            (chat_id, datetime.utcnow()),
        ).fetchone()
    return row["mute_until"] if row else None


#  Queries 

def get_items_since(since: datetime, severity: Optional[str] = None,
                    limit: int = 500) -> list[sqlite3.Row]:
    query = "SELECT * FROM items WHERE fetched_at >= ?"
    params: list = [since]
    if severity:
        query += " AND severity=?"
        params.append(severity)
    query += " ORDER BY internal_score DESC, published_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        return conn.execute(query, params).fetchall()


def get_unenriched_cves(limit: int = 50) -> list[sqlite3.Row]:
    """CVEs non enrichis qui ont besoin de NVD/EPSS."""
    with get_conn() as conn:
        return conn.execute(
            """SELECT * FROM items
               WHERE enriched=0
                 AND (item_type IN ('CVE','KEV','ADVISORY')
                      OR (external_id LIKE 'CVE-%'))
               ORDER BY internal_score DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()


def get_stats_since(since: datetime) -> dict:
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=?", (since,)
        ).fetchone()[0]
        by_sev = {
            r[0]: r[1] for r in conn.execute(
                "SELECT severity, COUNT(*) FROM items WHERE fetched_at>=? GROUP BY severity", (since,)
            ).fetchall()
        }
        by_type = {
            r[0]: r[1] for r in conn.execute(
                "SELECT item_type, COUNT(*) FROM items WHERE fetched_at>=? GROUP BY item_type", (since,)
            ).fetchall()
        }
        kev_count = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND is_kev=1", (since,)
        ).fetchone()[0]
        exploit_count = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND has_public_exploit=1", (since,)
        ).fetchone()[0]
        watchlist_count = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND on_watchlist=1", (since,)
        ).fetchone()[0]
        epss_high = conn.execute(
            "SELECT COUNT(*) FROM items WHERE fetched_at>=? AND epss_score>=0.5", (since,)
        ).fetchone()[0]
    return {
        "total": total,
        "by_severity": by_sev,
        "by_type": by_type,
        "kev_count": kev_count,
        "exploit_count": exploit_count,
        "watchlist_count": watchlist_count,
        "epss_high_count": epss_high,
    }


def get_top_items(since: datetime, n: int = 5) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """SELECT * FROM items WHERE fetched_at>=?
               ORDER BY internal_score DESC, published_at DESC LIMIT ?""",
            (since, n),
        ).fetchall()


#  Settings / Offset Telegram 

def set_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO settings(key,value,updated) VALUES(?,?,?) "
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
        return conn.execute(
            "INSERT INTO runs(started_at,mode) VALUES(?,?)",
            (datetime.utcnow(), mode),
        ).lastrowid

def finish_run(run_id: int, new_items: int, enriched: int,
               alerts_sent: int, errors: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE runs SET finished_at=?,new_items=?,enriched=?,alerts_sent=?,errors=? WHERE id=?",
            (datetime.utcnow(), new_items, enriched, alerts_sent, errors, run_id),
        )
