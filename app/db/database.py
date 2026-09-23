import gc
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


def finalize_readonly_snapshot(db_path: str) -> None:
    """Convert a finished database to a mount-safe (non-WAL) journal mode.

    The live SIEM runs in WAL for concurrency, but a WAL database cannot be
    opened from a read-only bind mount: SQLite still needs to write the -wal and
    -shm sidecars, which fails on a read-only file. The demo database is mounted
    read-only into Grafana, so checkpoint it and switch it to a rollback journal,
    leaving a single self-contained file that opens cleanly read-only.
    """
    # SQLite refuses to leave WAL mode while any other connection has the file
    # open, and callers reach the db through short-lived `with get_connection()`
    # blocks whose connections are closed by garbage collection, not on block
    # exit. Force a collection first so no stale handle silently blocks the
    # switch (which would otherwise fail quietly, leaving the db in WAL).
    gc.collect()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        mode = conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
    finally:
        conn.close()
    if mode != "delete":
        raise RuntimeError(
            f"Could not switch {db_path} out of WAL mode (still {mode!r}); "
            "another connection is holding the database open."
        )
