import sqlite3
from pathlib import Path


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str) -> None:
    schema = (Path(__file__).parent / "schema.sql").read_text()
    with get_connection(db_path) as conn:
        conn.executescript(schema)
