import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone


def get_db_path() -> str:
    cache_dir = Path(__file__).parent / "cache"
    cache_dir.mkdir(exist_ok=True)
    return str(cache_dir / "gravitas_cache.db")


def init_db() -> str:
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cache_key TEXT UNIQUE NOT NULL,
        module TEXT NOT NULL,
        result_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_hash TEXT NOT NULL,
        inputs_json TEXT NOT NULL,
        results_json TEXT NOT NULL,
        gravity_score INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()
    return db_path


def cache_get(key: str) -> dict | None:
    try:
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT result_json FROM cache WHERE cache_key=? AND expires_at > ?",
            (key, datetime.now(timezone.utc).isoformat()),
        )
        row = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row["result_json"])
    except Exception:
        pass
    return None


def cache_set(key: str, module: str, data: dict, ttl_hours: int = 24) -> None:
    try:
        db_path = get_db_path()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
        conn = sqlite3.connect(db_path)
        conn.execute(
            """INSERT INTO cache (cache_key, module, result_json, expires_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(cache_key) DO UPDATE SET
                 result_json=excluded.result_json,
                 expires_at=excluded.expires_at,
                 created_at=CURRENT_TIMESTAMP""",
            (key, module, json.dumps(data), expires_at),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def save_session(target_hash: str, inputs: dict, results: dict, gravity_score: int) -> None:
    try:
        init_db()
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO sessions (target_hash, inputs_json, results_json, gravity_score) VALUES (?, ?, ?, ?)",
            (target_hash, json.dumps(inputs), json.dumps(results), gravity_score),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
