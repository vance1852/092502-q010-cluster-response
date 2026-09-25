"""定义基础服务在模块边界使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Actor:
    """表示具有明确角色的后台操作者。"""

    actor_id: str
    display_name: str
    role: str
    organization_id: str
    active: bool


@dataclass(frozen=True)
class Site:
    """表示企业或监管组织下的业务场所。"""

    site_id: str
    organization_id: str
    name: str
    timezone_name: str
    version: int
    cluster_id: str | None = None


@dataclass(frozen=True)
class DomainRecord:
    """表示已经持久化的领域资料记录。"""

    record_id: str
    site_id: str
    category: str
    external_key: str
    payload: dict[str, Any]
    created_by: str
    created_at: str


@dataclass(frozen=True)
class WriteReceipt:
    """描述一次幂等写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool


@dataclass(frozen=True)
class Plan:
    """表示一个版本化应急预案。"""

    plan_id: str
    version: int
    cluster_id: str
    escalation_rule: dict[str, Any]
    lead_by_classification: dict[str, str]
    response_minutes_by_level: dict[str, int]
    published_by: str
    created_at: str


@dataclass(frozen=True)
class Signal:
    """表示企业上报的一条脱敏风险信号（含重复合并后的状态）。"""

    signal_id: str
    incident_id: str
    site_id: str
    organization_id: str
    fingerprint: str
    severity: str
    supply_code: str | None
    payload: dict[str, Any]
    occurred_at: str
    repeat_count: int
    in_appendix: bool
    created_by: str
    created_at: str
    reports: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class Incident:
    """表示由信号汇聚而成的应急事件。"""

    incident_id: str
    cluster_id: str
    signal_type: str
    plan_id: str
    plan_version: int
    level: int
    classification: str
    lead_actor_id: str
    lead_overridden: bool
    response_due_at: str
    status: str
    version: int
    created_at: str
    closed_at: str | None = None
    signals: list[Signal] = field(default_factory=list)

