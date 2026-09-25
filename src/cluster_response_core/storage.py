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
CREATE TABLE IF NOT EXISTS response_plans (
    plan_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    name TEXT NOT NULL,
    levels_json TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    default_level TEXT NOT NULL,
    group_keys_csv TEXT NOT NULL DEFAULT '',
    append_window_minutes INTEGER NOT NULL DEFAULT 1440,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(plan_id, version)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    group_key TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
    level TEXT NOT NULL,
    deadline_at TEXT,
    commander_actor_id TEXT,
    commander_version INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    FOREIGN KEY(plan_id, plan_version) REFERENCES response_plans(plan_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_open_group
    ON incidents(group_key, signal_type) WHERE status = 'open';
CREATE TABLE IF NOT EXISTS incident_signals (
    signal_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    dedup_key TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    max_severity TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('live', 'appendix')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(incident_id, dedup_key, phase)
);
CREATE TABLE IF NOT EXISTS signal_sources (
    signal_id TEXT NOT NULL REFERENCES incident_signals(signal_id),
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    organization_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('live', 'appendix')),
    report_count INTEGER NOT NULL CHECK(report_count >= 1),
    first_reported_at TEXT NOT NULL,
    last_reported_at TEXT NOT NULL,
    PRIMARY KEY(signal_id, site_id)
);
CREATE TABLE IF NOT EXISTS incident_command_history (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    actor_id TEXT NOT NULL,
    reason TEXT,
    assigned_by TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    PRIMARY KEY(incident_id, sequence)
);
CREATE TABLE IF NOT EXISTS standby_capacities (
    capacity_id TEXT PRIMARY KEY,
    owner_organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    site_id TEXT REFERENCES sites(site_id),
    resource_type TEXT NOT NULL,
    total_qty INTEGER NOT NULL CHECK(total_qty >= 0),
    shared_qty INTEGER NOT NULL CHECK(shared_qty >= 0),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capacity_allocations (
    allocation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    capacity_id TEXT NOT NULL REFERENCES standby_capacities(capacity_id),
    qty INTEGER NOT NULL CHECK(qty > 0),
    status TEXT NOT NULL CHECK(status IN ('reserved', 'confirmed', 'released')),
    release_reason TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_allocations_capacity ON capacity_allocations(capacity_id, status);
CREATE INDEX IF NOT EXISTS idx_allocations_incident ON capacity_allocations(incident_id);
CREATE INDEX IF NOT EXISTS idx_sources_organization ON signal_sources(organization_id);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        # 单连接被多线程 HTTP 服务共享：用进程内锁串行化事务，避免在同一连接上
        # 嵌套开启事务；跨连接/跨进程的并发正确性仍由 BEGIN IMMEDIATE 保证。
        self._transaction_lock = threading.RLock()
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        with self._transaction_lock:
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
