import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        with db:
            yield db
    finally:
        db.close()

def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript('''
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, scenario TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), timestamp TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','investigating','resolved')), created_at TEXT NOT NULL, host TEXT NOT NULL, user TEXT NOT NULL, evidence TEXT NOT NULL, UNIQUE(run_id,rule_id,host,user));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), created_at TEXT NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit(incident_id);
        ''')

def incident(row):
    result = dict(row)
    result["evidence"] = json.loads(result["evidence"])
    return result
