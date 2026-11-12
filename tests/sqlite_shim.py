"""Lets the automatic tests run the real app code on SQLite instead of MySQL.
It only translates the small differences (%s placeholders, FOR UPDATE, dict rows)."""
import sqlite3
from datetime import datetime
from decimal import Decimal
from pathlib import Path

sqlite3.register_adapter(Decimal, str)
sqlite3.register_converter("DATETIME", lambda b: datetime.strptime(b.decode(), "%Y-%m-%d %H:%M:%S"))


OPEN = set()        # connections that are open right now (the tests check that none is left open: Windows cannot delete a file that is still open)


class ShimCursor:
    def __init__(self, conn, fail_on):
        self._cur = conn.cursor()
        self._fail_on = fail_on

    def execute(self, sql, args=()):
        for marker in self._fail_on:                       # lets a test simulate a crash in the middle of an order
            if marker in sql:
                raise RuntimeError("simulated database failure")
        self._cur.execute(sql.replace("%s", "?").replace(" FOR UPDATE", ""), tuple(args))
        return self

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        return self._cur.lastrowid

    def fetchone(self):
        row = self._cur.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(r) for r in self._cur.fetchall()]

    def close(self):
        self._cur.close()


class ShimConnection:
    def __init__(self, path, fail_on):
        self._conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._fail_on = fail_on
        OPEN.add(self)

    def cursor(self):
        return ShimCursor(self._conn, self._fail_on)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        OPEN.discard(self)
        self._conn.close()


def create_database(path):
    conn = sqlite3.connect(path)
    conn.executescript((Path(__file__).parent / "sqlite_schema.sql").read_text())
    conn.commit()
    conn.close()


def make_factory(path, fail_on=None):
    markers = fail_on if fail_on is not None else []
    return lambda: ShimConnection(path, markers)