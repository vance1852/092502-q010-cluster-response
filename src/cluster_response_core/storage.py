"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    regulator INTEGER NOT NULL DEFAULT 0 CHECK(regulator IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    cluster_id TEXT,
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    cluster_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    published_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(plan_id, version)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    opened_by TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    level INTEGER NOT NULL CHECK(level >= 1),
    classification TEXT NOT NULL,
    lead_actor_id TEXT NOT NULL,
    lead_overridden INTEGER NOT NULL DEFAULT 0 CHECK(lead_overridden IN (0, 1)),
    response_due_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS incident_signals (
    signal_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    site_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    supply_code TEXT,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    repeat_count INTEGER NOT NULL DEFAULT 1 CHECK(repeat_count >= 1),
    in_appendix INTEGER NOT NULL DEFAULT 0 CHECK(in_appendix IN (0, 1)),
    late_count INTEGER NOT NULL DEFAULT 0 CHECK(late_count >= 0),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, site_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS signal_reports (
    report_id TEXT PRIMARY KEY,
    signal_id TEXT NOT NULL REFERENCES incident_signals(signal_id),
    request_id TEXT,
    reporter_actor_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    reported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capabilities (
    capability_id TEXT PRIMARY KEY,
    owner_org_id TEXT NOT NULL REFERENCES organizations(organization_id),
    site_id TEXT REFERENCES sites(site_id),
    kind TEXT NOT NULL CHECK(kind IN ('equipment', 'technician')),
    total_qty INTEGER NOT NULL CHECK(total_qty >= 0),
    shared_qty INTEGER NOT NULL CHECK(shared_qty >= 0),
    reserved_qty INTEGER NOT NULL DEFAULT 0 CHECK(reserved_qty >= 0),
    confirmed_qty INTEGER NOT NULL DEFAULT 0 CHECK(confirmed_qty >= 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(shared_qty <= total_qty),
    CHECK(reserved_qty + confirmed_qty <= shared_qty)
);
CREATE TABLE IF NOT EXISTS allocations (
    allocation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    capability_id TEXT NOT NULL REFERENCES capabilities(capability_id),
    capability_version INTEGER NOT NULL,
    qty INTEGER NOT NULL CHECK(qty > 0),
    confirmed_qty INTEGER NOT NULL DEFAULT 0 CHECK(confirmed_qty >= 0),
    released_qty INTEGER NOT NULL DEFAULT 0 CHECK(released_qty >= 0),
    revoked_qty INTEGER NOT NULL DEFAULT 0 CHECK(revoked_qty >= 0),
    status TEXT NOT NULL CHECK(status IN ('reserved', 'partially_confirmed',
                                         'confirmed', 'released', 'revoked')),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    request_id TEXT NOT NULL,
    reserved_by TEXT NOT NULL,
    confirmed_by TEXT,
    reserved_at TEXT NOT NULL,
    confirmed_at TEXT,
    CHECK(confirmed_qty + released_qty + revoked_qty <= qty),
    UNIQUE(request_id, capability_id)
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)
        # 单连接被 HTTP 工作线程共享，用锁把每个事务串行化，避免语句交错。
        self._tx_lock = threading.RLock()

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交；多线程下整段事务串行执行。"""

        with self._tx_lock:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
