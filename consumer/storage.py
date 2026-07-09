import logging
import sqlite3

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS flagged_certs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_domain TEXT    NOT NULL,
    matched_seed     TEXT    NOT NULL,
    flag_reason      TEXT    NOT NULL,
    score            INTEGER NOT NULL,
    edit_distance    INTEGER,
    issuer           TEXT,
    not_before       INTEGER,
    not_after        INTEGER,
    seen_at          INTEGER NOT NULL,
    fingerprint      TEXT    NOT NULL UNIQUE,
    created_at       INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_seen_at      ON flagged_certs (seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_matched_seed ON flagged_certs (matched_seed);
CREATE INDEX IF NOT EXISTS idx_flag_reason  ON flagged_certs (flag_reason);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.executescript(_DDL)
    conn.commit()
    return conn


def save_cert(conn: sqlite3.Connection, record: dict) -> None:
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO flagged_certs
                (candidate_domain, matched_seed, flag_reason, score, edit_distance,
                 issuer, not_before, not_after, seen_at, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record['candidate_domain'],
                record['matched_seed'],
                record['flag_reason'],
                record['score'],
                record.get('edit_distance'),
                record.get('issuer'),
                record.get('not_before'),
                record.get('not_after'),
                int(record['seen_at']) if record.get('seen_at') else 0,
                record['fingerprint'],
            ),
        )
        conn.commit()
    except sqlite3.Error as exc:
        logger.error('db write failed: %s', exc)
