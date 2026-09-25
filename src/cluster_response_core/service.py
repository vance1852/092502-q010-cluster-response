"""提供主体、场所、领域资料和审计查询能力。"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .audit import append_event, canonical_json, digest, verify_chain
from .clock import Clock, SystemClock
from .domain import is_allowed_category
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .incidents import (
    CLASSIFICATION_REGIONAL,
    CLASSIFICATION_SHARED,
    CLASSIFICATION_SINGLE,
    SEVERITY_ORDER,
    aggregate_signals,
    classify,
    normalize_severity,
    normalize_supply_code,
    resolve_level,
)
from .models import Actor, DomainRecord, Site, WriteReceipt
from .storage import Database


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
ROLES = frozenset({"admin", "operator", "reviewer", "auditor"})
CLASSIFICATION_RANK = {
    CLASSIFICATION_SINGLE: 1,
    CLASSIFICATION_SHARED: 2,
    CLASSIFICATION_REGIONAL: 3,
}
CLASSIFICATIONS = frozenset(CLASSIFICATION_RANK)
CAPABILITY_KINDS = frozenset({"equipment", "technician"})


class DomainService:
    """协调权限、幂等、事务和审计规则。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 200) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"], row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _require(self, actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _is_regulator_actor(self, connection, actor: Actor) -> bool:
        """监管角色或隶属监管组织（街道指挥侧）的操作者拥有完整态势视图。"""

        if actor.role in ("admin", "reviewer", "auditor"):
            return True
        row = connection.execute(
            "SELECT regulator FROM organizations WHERE organization_id=?",
            (actor.organization_id,),
        ).fetchone()
        return bool(row and row["regulator"])

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any], create: Callable[[], tuple[str, str, dict[str, Any]]]) -> WriteReceipt:
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute("SELECT * FROM request_receipts WHERE request_id=?", (request_id,)).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return WriteReceipt(request_id, row["resource_type"], row["resource_id"], True)
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,response_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id, canonical_json(response), self._now()),
        )
        return WriteReceipt(request_id, resource_type, resource_id, False)

    def register_organization(self, *, request_id: str, actor_id: str,
                              organization_id: str, name: str,
                              is_regulator: bool = False) -> WriteReceipt:
        payload = {"actor_id": actor_id, "organization_id": organization_id, "name": name,
                   "is_regulator": bool(is_regulator)}
        with self.database.transaction(immediate=True) as connection:
            existing_actors = connection.execute("SELECT COUNT(*) AS count FROM actors").fetchone()["count"]
            if existing_actors:
                actor = self._actor(connection, actor_id)
                self._require(actor, "admin")
            elif actor_id != "bootstrap":
                raise PermissionDenied("首次建档必须使用 bootstrap")
            organization_id = self._identifier(organization_id, "organization_id")
            name = self._text(name, "name")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO organizations(organization_id,name,regulator,created_at) VALUES(?,?,?,?)",
                        (organization_id, name, 1 if is_regulator else 0, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("组织编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="organization.registered",
                             resource_type="organization", resource_id=organization_id,
                             detail={"name": name, "is_regulator": bool(is_regulator)},
                             occurred_at=self._now())
                return "organization", organization_id, {"organization_id": organization_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_organization", payload=payload, create=create)

    def register_actor(self, *, request_id: str, actor_id: str, new_actor_id: str,
                       display_name: str, role: str, organization_id: str) -> WriteReceipt:
        payload = {"actor_id": actor_id, "new_actor_id": new_actor_id, "display_name": display_name,
                   "role": role, "organization_id": organization_id}
        with self.database.transaction(immediate=True) as connection:
            count = connection.execute("SELECT COUNT(*) AS count FROM actors").fetchone()["count"]
            if count:
                actor = self._actor(connection, actor_id)
                self._require(actor, "admin")
            elif actor_id != "bootstrap":
                raise PermissionDenied("首位管理员必须由 bootstrap 创建")
            new_actor_id = self._identifier(new_actor_id, "new_actor_id")
            display_name = self._text(display_name, "display_name")
            if role not in ROLES:
                raise ValidationError("role 不在允许范围内")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?", (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO actors(actor_id,display_name,role,organization_id,active,created_at) VALUES(?,?,?,?,1,?)",
                        (new_actor_id, display_name, role, organization_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("操作者编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="actor.registered",
                             resource_type="actor", resource_id=new_actor_id,
                             detail={"display_name": display_name, "role": role, "organization_id": organization_id},
                             occurred_at=self._now())
                return "actor", new_actor_id, {"actor_id": new_actor_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_actor", payload=payload, create=create)

    def register_site(self, *, request_id: str, actor_id: str, site_id: str,
                      organization_id: str, name: str, timezone_name: str,
                      cluster_id: str | None = None) -> WriteReceipt:
        payload = {"actor_id": actor_id, "site_id": site_id, "organization_id": organization_id,
                   "name": name, "timezone_name": timezone_name, "cluster_id": cluster_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            if actor.organization_id != organization_id and actor.role != "admin":
                raise PermissionDenied("不能为其他组织登记场所")
            site_id = self._identifier(site_id, "site_id")
            name = self._text(name, "name")
            timezone_name = self._text(timezone_name, "timezone_name", 80)
            if cluster_id is not None:
                cluster_id = self._identifier(cluster_id, "cluster_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO sites(site_id,organization_id,cluster_id,name,timezone_name,version,created_at) "
                        "VALUES(?,?,?,?,?,1,?)",
                        (site_id, organization_id, cluster_id, name, timezone_name, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("场所编号已经存在或组织无效") from exc
                append_event(connection, actor_id=actor_id, action="site.registered",
                             resource_type="site", resource_id=site_id,
                             detail={"organization_id": organization_id, "cluster_id": cluster_id,
                                     "name": name, "timezone_name": timezone_name},
                             occurred_at=self._now())
                return "site", site_id, {"site_id": site_id, "version": 1, "cluster_id": cluster_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_site", payload=payload, create=create)

    def record_domain_data(self, *, request_id: str, actor_id: str, site_id: str,
                           category: str, external_key: str, data: dict[str, Any]) -> WriteReceipt:
        if not isinstance(data, dict) or not data:
            raise ValidationError("data 必须是非空对象")
        payload = {"actor_id": actor_id, "site_id": site_id, "category": category,
                   "external_key": external_key, "data": data}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            site = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if site is None:
                raise NotFoundError("场所不存在")
            if actor.organization_id != site["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能写入其他组织的场所")
            if not is_allowed_category(category):
                raise ValidationError("资料类别不属于当前项目")
            external_key = self._identifier(external_key, "external_key")
            data_hash = digest(data)

            def create() -> tuple[str, str, dict[str, Any]]:
                existing = connection.execute(
                    "SELECT * FROM domain_records WHERE site_id=? AND category=? AND external_key=?",
                    (site_id, category, external_key),
                ).fetchone()
                if existing:
                    if existing["payload_hash"] != data_hash:
                        raise ConflictError("同一业务键已经登记不同内容")
                    return "domain_record", existing["record_id"], {"record_id": existing["record_id"]}
                record_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO domain_records(record_id,site_id,category,external_key,payload_json,payload_hash,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (record_id, site_id, category, external_key, canonical_json(data), data_hash, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="domain_data.recorded",
                             resource_type="domain_record", resource_id=record_id,
                             detail={"site_id": site_id, "category": category, "external_key": external_key,
                                     "payload_hash": data_hash}, occurred_at=self._now())
                return "domain_record", record_id, {"record_id": record_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="record_domain_data", payload=payload, create=create)

    # ------------------------------------------------------------------
    # 集群联防：版本化预案
    # ------------------------------------------------------------------

    def _parse_ts(self, value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("时间格式必须是 ISO 8601") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _iso(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _qty(self, value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationError(f"{field} 必须是非负整数")
        return value

    def _validate_plan_payload(self, connection, payload: dict[str, Any]) -> None:
        rule = payload.get("escalation_rule")
        if not isinstance(rule, dict) or not isinstance(rule.get("rules"), list):
            raise ValidationError("escalation_rule.rules 必须是列表")
        default_level = int(rule.get("default_level", 0))
        if default_level not in (1, 2, 3):
            raise ValidationError("escalation_rule.default_level 必须是 1/2/3")
        for entry in rule["rules"]:
            if not isinstance(entry, dict) or int(entry.get("level", 0)) not in (1, 2, 3):
                raise ValidationError("升级规则条目必须包含 1/2/3 级 level")
            if "classification" in entry and entry["classification"] not in CLASSIFICATIONS:
                raise ValidationError("升级规则引用了未知分类")
            if "min_severity" in entry and entry["min_severity"] not in SEVERITY_ORDER:
                raise ValidationError("升级规则引用了未知严重度")
        leads = payload.get("lead_by_classification")
        if not isinstance(leads, dict) or set(leads) != set(CLASSIFICATION_RANK):
            raise ValidationError("lead_by_classification 必须覆盖全部三种事件分类")
        for actor_id in leads.values():
            row = connection.execute("SELECT active FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
            if row is None or not row["active"]:
                raise ValidationError(f"牵头人 {actor_id} 不存在或已停用")
        minutes = payload.get("response_minutes_by_level")
        if not isinstance(minutes, dict):
            raise ValidationError("response_minutes_by_level 必须是对象")
        for key in ("1", "2", "3"):
            value = minutes.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValidationError(f"级别 {key} 的响应时限必须是正整数分钟")

    def publish_plan(self, *, request_id: str, actor_id: str, plan_id: str, cluster_id: str,
                     escalation_rule: dict[str, Any], lead_by_classification: dict[str, str],
                     response_minutes_by_level: dict[str, int]) -> WriteReceipt:
        """发布一个新版本的应急预案；同 plan_id 内容逐版本追加。"""

        payload = {"plan_id": plan_id, "cluster_id": cluster_id, "escalation_rule": escalation_rule,
                   "lead_by_classification": lead_by_classification,
                   "response_minutes_by_level": response_minutes_by_level}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            plan_id = self._identifier(plan_id, "plan_id")
            cluster_id = self._identifier(cluster_id, "cluster_id")
            self._validate_plan_payload(connection, payload)
            payload_hash = digest(payload)

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT version, payload_hash FROM plans WHERE plan_id=? ORDER BY version DESC LIMIT 1",
                    (plan_id,),
                ).fetchone()
                version = (row["version"] + 1) if row else 1
                if row and row["payload_hash"] == payload_hash:
                    raise ConflictError("预案内容与最新版本一致，无需重复发布")
                connection.execute(
                    "INSERT INTO plans(plan_id,version,cluster_id,payload_json,payload_hash,published_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (plan_id, version, cluster_id, canonical_json(payload), payload_hash, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="plan.published",
                             resource_type="plan", resource_id=f"{plan_id}:{version}",
                             detail={"plan_id": plan_id, "version": version, "cluster_id": cluster_id,
                                     "payload_hash": payload_hash}, occurred_at=self._now())
                return "plan", f"{plan_id}:{version}", {"plan_id": plan_id, "version": version}

            return self._idempotent(connection, request_id=request_id,
                                    action="publish_plan", payload=payload, create=create)

    def _latest_plan(self, connection, cluster_id: str):
        row = connection.execute(
            "SELECT * FROM plans WHERE cluster_id=? ORDER BY version DESC LIMIT 1", (cluster_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("该集群尚无生效预案")
        return row

    # ------------------------------------------------------------------
    # 集群联防：脱敏信号归并与事件升级
    # ------------------------------------------------------------------

    def _sanitize_signal_payload(self, data: Any) -> dict[str, Any]:
        if data is None:
            return {}
        if not isinstance(data, dict) or len(data) > 20:
            raise ValidationError("信号载荷必须是至多 20 个键的对象")
        allowed = (str, int, float, bool, type(None))
        result: dict[str, Any] = {}
        for key, value in data.items():
            if not isinstance(key, str) or not key or len(key) > 60:
                raise ValidationError("信号载荷键必须是 1-60 字符的字符串")
            if not isinstance(value, allowed):
                raise ValidationError("信号载荷只能携带标量脱敏字段")
            if isinstance(value, str) and len(value) > 200:
                raise ValidationError("信号载荷字符串不能超过 200 字符")
            result[key] = value
        return result

    def _signal_aggregate_facts(self, connection, incident_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT sig.*, s.organization_id FROM incident_signals sig "
            "JOIN sites s ON s.site_id = sig.site_id "
            "WHERE sig.incident_id=? AND sig.in_appendix=0 ORDER BY sig.created_at, sig.signal_id",
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _recompute_incident(self, connection, incident_row, facts: list[dict[str, Any]]) -> bool:
        """依据全部在档信号重算分类、级别、牵头人与响应时限。返回是否发生变化。"""

        plan = json.loads(self._plan_payload_json(connection, incident_row))
        aggregate = aggregate_signals(facts)
        shared_supply = bool(aggregate["shared_supply_codes"])
        new_classification = classify(aggregate["org_count"], aggregate["max_severity"], shared_supply)
        new_level = resolve_level(plan["escalation_rule"], new_classification,
                                  aggregate["max_severity"], aggregate["org_count"])
        changes: dict[str, Any] = {}
        if new_classification != incident_row["classification"]:
            changes["classification"] = {"from": incident_row["classification"], "to": new_classification}
        if new_level != incident_row["level"]:
            changes["level"] = {"from": incident_row["level"], "to": new_level}
        new_lead = plan["lead_by_classification"][new_classification]
        if not incident_row["lead_overridden"] and new_lead != incident_row["lead_actor_id"]:
            changes["lead_actor_id"] = {"from": incident_row["lead_actor_id"], "to": new_lead}
        if not changes:
            return False
        minutes = int(plan["response_minutes_by_level"][str(new_level)])
        due_at = self._iso(self._parse_ts(incident_row["created_at"]) + timedelta(minutes=minutes))
        connection.execute(
            "UPDATE incidents SET classification=?, level=?, lead_actor_id=?, response_due_at=?, "
            "version=version+1 WHERE incident_id=?",
            (new_classification, new_level,
             changes.get("lead_actor_id", {}).get("to", incident_row["lead_actor_id"]),
             due_at, incident_row["incident_id"]),
        )
        return True

    def _plan_payload_json(self, connection, incident_row) -> str:
        row = connection.execute(
            "SELECT payload_json FROM plans WHERE plan_id=? AND version=?",
            (incident_row["plan_id"], incident_row["plan_version"]),
        ).fetchone()
        if row is None:
            raise NotFoundError("事件绑定的预案版本已不存在")
        return row["payload_json"]

    def report_signal(self, *, request_id: str, actor_id: str, site_id: str, signal_type: str,
                      fingerprint: str, severity: str, supply_code: str | None = None,
                      occurred_at: str | None = None, payload: dict[str, Any] | None = None
                      ) -> WriteReceipt:
        """上报一条脱敏风险信号，自动建事件、合并重复信号或进入关闭事件附录。"""

        signal_type = str(signal_type).strip()
        if not signal_type or len(signal_type) > 60:
            raise ValidationError("signal_type 必须是 1-60 字符的字符串")
        severity = normalize_severity(severity)
        supply_code = normalize_supply_code(supply_code)
        fingerprint = self._identifier(fingerprint, "fingerprint")
        payload = self._sanitize_signal_payload(payload)
        signal_time = self._parse_ts(occurred_at) if occurred_at else self.clock.now()
        body = {"site_id": site_id, "signal_type": signal_type, "fingerprint": fingerprint,
                "severity": severity, "supply_code": supply_code,
                "occurred_at": self._iso(signal_time), "payload": payload}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            site = connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
            if site is None:
                raise NotFoundError("场所不存在")
            if actor.organization_id != site["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能代替其他企业上报信号")
            if not site["cluster_id"]:
                raise ValidationError("场所尚未加入产业集群")
            cluster_id = site["cluster_id"]

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                open_incident = connection.execute(
                    "SELECT * FROM incidents WHERE cluster_id=? AND signal_type=? AND status='open' "
                    "ORDER BY created_at DESC LIMIT 1",
                    (cluster_id, signal_type),
                ).fetchone()
                if open_incident is not None:
                    return self._merge_signal(connection, open_incident, actor, body, now, appendix=False)
                closed_incident = connection.execute(
                    "SELECT * FROM incidents WHERE cluster_id=? AND signal_type=? AND status='closed' "
                    "ORDER BY closed_at DESC LIMIT 1",
                    (cluster_id, signal_type),
                ).fetchone()
                if closed_incident is not None:
                    return self._merge_signal(connection, closed_incident, actor, body, now, appendix=True)
                return self._open_incident(connection, cluster_id, actor, body, now)

            return self._idempotent(connection, request_id=request_id,
                                    action="report_signal",
                                    payload={"actor_id": actor_id, **body}, create=create)

    def open_incident(self, *, request_id: str, actor_id: str, cluster_id: str,
                      signal_type: str) -> WriteReceipt:
        """指挥人员就某类告警开启新一轮事件（用于关闭后再次发生的联防波次）。"""

        signal_type = str(signal_type).strip()
        if not signal_type or len(signal_type) > 60:
            raise ValidationError("signal_type 必须是 1-60 字符的字符串")
        payload = {"cluster_id": cluster_id, "signal_type": signal_type}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_command_side(connection, actor)
            cluster_id = self._identifier(cluster_id, "cluster_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                existing = connection.execute(
                    "SELECT incident_id FROM incidents WHERE cluster_id=? AND signal_type=? "
                    "AND status='open'",
                    (cluster_id, signal_type),
                ).fetchone()
                if existing is not None:
                    raise ConflictError("该集群此类告警已有进行中的事件")
                now = self._now()
                plan_row = self._latest_plan(connection, cluster_id)
                plan = json.loads(plan_row["payload_json"])
                classification = CLASSIFICATION_SINGLE
                level = resolve_level(plan["escalation_rule"], classification, "low", 0)
                lead_actor_id = plan["lead_by_classification"][classification]
                minutes = int(plan["response_minutes_by_level"][str(level)])
                due_at = self._iso(self._parse_ts(now) + timedelta(minutes=minutes))
                incident_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO incidents(incident_id,cluster_id,signal_type,opened_by,plan_id,plan_version,"
                    "level,classification,lead_actor_id,response_due_at,status,version,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,'open',1,?)",
                    (incident_id, cluster_id, signal_type, actor_id, plan_row["plan_id"],
                     plan_row["version"], level, classification, lead_actor_id, due_at, now),
                )
                append_event(connection, actor_id=actor_id, action="incident.opened",
                             resource_type="incident", resource_id=incident_id,
                             detail={"cluster_id": cluster_id, "signal_type": signal_type,
                                     "manual": True, "classification": classification, "level": level,
                                     "lead_actor_id": lead_actor_id, "plan_id": plan_row["plan_id"],
                                     "plan_version": plan_row["version"]}, occurred_at=now)
                return "incident", incident_id, {"incident_id": incident_id, "signals": 0}

            return self._idempotent(connection, request_id=request_id,
                                    action="open_incident", payload=payload, create=create)

    def _open_incident(self, connection, cluster_id: str, actor: Actor,
                       body: dict[str, Any], now: str) -> tuple[str, str, dict[str, Any]]:
        plan_row = self._latest_plan(connection, cluster_id)
        plan = json.loads(plan_row["payload_json"])
        site = connection.execute("SELECT * FROM sites WHERE site_id=?", (body["site_id"],)).fetchone()
        classification = classify(1, body["severity"], False)
        level = resolve_level(plan["escalation_rule"], classification, body["severity"], 1)
        lead_actor_id = plan["lead_by_classification"][classification]
        minutes = int(plan["response_minutes_by_level"][str(level)])
        due_at = self._iso(self._parse_ts(now) + timedelta(minutes=minutes))
        incident_id = uuid.uuid4().hex
        connection.execute(
            "INSERT INTO incidents(incident_id,cluster_id,signal_type,opened_by,plan_id,plan_version,"
            "level,classification,lead_actor_id,response_due_at,status,version,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,'open',1,?)",
            (incident_id, cluster_id, body["signal_type"], actor.actor_id,
             plan_row["plan_id"], plan_row["version"], level, classification, lead_actor_id, due_at, now),
        )
        signal_id = self._insert_signal(connection, incident_id, actor, body, now, appendix=False)
        append_event(connection, actor_id=actor.actor_id, action="incident.opened",
                     resource_type="incident", resource_id=incident_id,
                     detail={"cluster_id": cluster_id, "signal_type": body["signal_type"],
                             "classification": classification,
                             "level": level, "lead_actor_id": lead_actor_id,
                             "plan_id": plan_row["plan_id"], "plan_version": plan_row["version"],
                             "signal_id": signal_id}, occurred_at=now)
        return "incident", incident_id, {"incident_id": incident_id, "signal_id": signal_id, "appendix": False}

    def _insert_signal(self, connection, incident_id: str, actor: Actor,
                       body: dict[str, Any], now: str, *, appendix: bool) -> str:
        signal_id = uuid.uuid4().hex
        connection.execute(
            "INSERT INTO incident_signals(signal_id,incident_id,site_id,fingerprint,severity,supply_code,"
            "payload_json,occurred_at,repeat_count,in_appendix,late_count,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,1,?,0,?,?)",
            (signal_id, incident_id, body["site_id"], body["fingerprint"], body["severity"],
             body["supply_code"], canonical_json(body["payload"]), body["occurred_at"],
             1 if appendix else 0, actor.actor_id, now),
        )
        connection.execute(
            "INSERT INTO signal_reports(report_id,signal_id,reporter_actor_id,payload_hash,reported_at) "
            "VALUES(?,?,?,?,?)",
            (uuid.uuid4().hex, signal_id, actor.actor_id, digest(body), now),
        )
        return signal_id

    def _merge_signal(self, connection, incident_row, actor: Actor, body: dict[str, Any],
                      now: str, *, appendix: bool) -> tuple[str, str, dict[str, Any]]:
        existing = connection.execute(
            "SELECT * FROM incident_signals WHERE incident_id=? AND site_id=? AND fingerprint=?",
            (incident_row["incident_id"], body["site_id"], body["fingerprint"]),
        ).fetchone()
        if existing is not None:
            if appendix:
                # 关闭后到达的重复信号只累计附录迟到计数，不改变终态快照的 repeat_count
                connection.execute(
                    "UPDATE incident_signals SET late_count=late_count+1 WHERE signal_id=?",
                    (existing["signal_id"],),
                )
            else:
                connection.execute(
                    "UPDATE incident_signals SET repeat_count=repeat_count+1 WHERE signal_id=?",
                    (existing["signal_id"],),
                )
            connection.execute(
                "INSERT INTO signal_reports(report_id,signal_id,reporter_actor_id,payload_hash,reported_at) "
                "VALUES(?,?,?,?,?)",
                (uuid.uuid4().hex, existing["signal_id"], actor.actor_id, digest(body), now),
            )
            signal_id = existing["signal_id"]
            if appendix:
                append_event(connection, actor_id=actor.actor_id, action="signal.appendixed",
                             resource_type="signal", resource_id=signal_id,
                             detail={"incident_id": incident_row["incident_id"], "repeat": True,
                                     "late_count": existing["late_count"] + 1},
                             occurred_at=now)
                return "signal", signal_id, {"incident_id": incident_row["incident_id"],
                                             "signal_id": signal_id, "merged": True, "appendix": True}
            # 重复信号若严重度升高，则抬升该信号的最高严重度，并重算事件分级
            escalated = (SEVERITY_ORDER[body["severity"]]
                         > SEVERITY_ORDER[existing["severity"]])
            if escalated:
                connection.execute(
                    "UPDATE incident_signals SET severity=? WHERE signal_id=?",
                    (body["severity"], existing["signal_id"]),
                )
            append_event(connection, actor_id=actor.actor_id, action="signal.merged",
                         resource_type="signal", resource_id=signal_id,
                         detail={"incident_id": incident_row["incident_id"],
                                 "repeat_count": existing["repeat_count"] + 1,
                                 "severity_escalated": escalated}, occurred_at=now)
            if escalated:
                facts = self._signal_aggregate_facts(connection, incident_row["incident_id"])
                self._recompute_incident(connection, incident_row, facts)
                refreshed = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_row["incident_id"],)
                ).fetchone()
                append_event(connection, actor_id=actor.actor_id, action="incident.reassessed",
                             resource_type="incident", resource_id=incident_row["incident_id"],
                             detail={"classification": refreshed["classification"],
                                     "level": refreshed["level"],
                                     "lead_actor_id": refreshed["lead_actor_id"],
                                     "trigger": "duplicate_severity"}, occurred_at=now)
            return "signal", signal_id, {"incident_id": incident_row["incident_id"],
                                         "signal_id": signal_id, "merged": True, "appendix": False}
        signal_id = self._insert_signal(connection, incident_row["incident_id"], actor, body, now,
                                        appendix=appendix)
        if appendix:
            append_event(connection, actor_id=actor.actor_id, action="signal.appendixed",
                         resource_type="signal", resource_id=signal_id,
                         detail={"incident_id": incident_row["incident_id"], "repeat": False},
                         occurred_at=now)
            return "signal", signal_id, {"incident_id": incident_row["incident_id"],
                                         "signal_id": signal_id, "merged": False, "appendix": True}
        facts = self._signal_aggregate_facts(connection, incident_row["incident_id"])
        changed = self._recompute_incident(connection, incident_row, facts)
        refreshed = connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_row["incident_id"],)
        ).fetchone()
        append_event(connection, actor_id=actor.actor_id, action="signal.reported",
                     resource_type="signal", resource_id=signal_id,
                     detail={"incident_id": incident_row["incident_id"]}, occurred_at=now)
        if changed:
            append_event(connection, actor_id=actor.actor_id, action="incident.reassessed",
                         resource_type="incident", resource_id=incident_row["incident_id"],
                         detail={"classification": refreshed["classification"], "level": refreshed["level"],
                                 "lead_actor_id": refreshed["lead_actor_id"]}, occurred_at=now)
        return "incident", incident_row["incident_id"], {"incident_id": incident_row["incident_id"],
                                                         "signal_id": signal_id, "appendix": False}

    def close_incident(self, *, request_id: str, actor_id: str, incident_id: str) -> WriteReceipt:
        """关闭事件；关闭后到达的信号只进入附录，终态不再变化。"""

        payload = {"incident_id": incident_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident_id = self._identifier(incident_id, "incident_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("事件不存在")
                if row["status"] == "closed":
                    raise ConflictError("事件已经关闭")
                self._require_commander(connection, actor, row)
                now = self._now()
                connection.execute(
                    "UPDATE incidents SET status='closed', closed_at=?, version=version+1 WHERE incident_id=?",
                    (now, incident_id),
                )
                # 关闭时自动释放尚未确认的预占，使共享量回到可调度池；已确认调用保留。
                pending = connection.execute(
                    "SELECT * FROM allocations WHERE incident_id=? "
                    "AND qty-confirmed_qty-released_qty-revoked_qty > 0",
                    (incident_id,),
                ).fetchall()
                released_summary = []
                for alloc in pending:
                    outstanding = (alloc["qty"] - alloc["confirmed_qty"]
                                   - alloc["released_qty"] - alloc["revoked_qty"])
                    new_released = alloc["released_qty"] + outstanding
                    status = self._allocation_status(alloc["confirmed_qty"], new_released,
                                                     alloc["revoked_qty"], alloc["qty"])
                    connection.execute(
                        "UPDATE allocations SET released_qty=?, status=?, version=version+1 "
                        "WHERE allocation_id=?",
                        (new_released, status, alloc["allocation_id"]),
                    )
                    connection.execute(
                        "UPDATE capabilities SET reserved_qty=reserved_qty-?, version=version+1 "
                        "WHERE capability_id=?",
                        (outstanding, alloc["capability_id"]),
                    )
                    released_summary.append({"allocation_id": alloc["allocation_id"],
                                             "capability_id": alloc["capability_id"],
                                             "qty": outstanding, "status": status})
                append_event(connection, actor_id=actor_id, action="incident.closed",
                             resource_type="incident", resource_id=incident_id,
                             detail={"closed_at": now, "auto_released": released_summary},
                             occurred_at=now)
                return "incident", incident_id, {"incident_id": incident_id, "closed_at": now,
                                                 "auto_released": released_summary}

            return self._idempotent(connection, request_id=request_id,
                                    action="close_incident", payload=payload, create=create)

    def reassign_lead(self, *, request_id: str, actor_id: str, incident_id: str,
                      new_lead_actor_id: str) -> WriteReceipt:
        """由指挥人员指定唯一牵头人；手动指定后不再被自动规则覆盖。"""

        payload = {"incident_id": incident_id, "new_lead_actor_id": new_lead_actor_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident_id = self._identifier(incident_id, "incident_id")
            new_lead_actor_id = self._identifier(new_lead_actor_id, "new_lead_actor_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                target = connection.execute(
                    "SELECT active FROM actors WHERE actor_id=?", (new_lead_actor_id,)
                ).fetchone()
                if target is None or not target["active"]:
                    raise ValidationError("新牵头人不存在或已停用")
                row = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("事件不存在")
                self._require_command_side(connection, actor)
                if row["status"] == "closed":
                    raise ConflictError("已关闭事件不能更换牵头人")
                connection.execute(
                    "UPDATE incidents SET lead_actor_id=?, lead_overridden=1, version=version+1 "
                    "WHERE incident_id=?",
                    (new_lead_actor_id, incident_id),
                )
                append_event(connection, actor_id=actor_id, action="incident.lead_reassigned",
                             resource_type="incident", resource_id=incident_id,
                             detail={"from": row["lead_actor_id"], "to": new_lead_actor_id},
                             occurred_at=self._now())
                return "incident", incident_id, {"incident_id": incident_id,
                                                 "lead_actor_id": new_lead_actor_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="reassign_lead", payload=payload, create=create)

    def adopt_plan_version(self, *, request_id: str, actor_id: str, incident_id: str,
                           plan_version: int | None = None) -> WriteReceipt:
        """让进行中的事件采用更新的预案版本，并重算级别、牵头人与响应时限。"""

        if plan_version is not None and (isinstance(plan_version, bool) or not isinstance(plan_version, int)):
            raise ValidationError("plan_version 必须是整数")
        payload = {"incident_id": incident_id, "plan_version": plan_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident_id = self._identifier(incident_id, "incident_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("事件不存在")
                self._require_command_side(connection, actor)
                if row["status"] == "closed":
                    raise ConflictError("已关闭事件不能改用预案版本")
                target_version = plan_version
                target = connection.execute(
                    "SELECT * FROM plans WHERE plan_id=? ORDER BY version DESC LIMIT 1",
                    (row["plan_id"],),
                ).fetchone()
                if target is None:
                    raise NotFoundError("预案不存在")
                if target_version is None:
                    target_version = target["version"]
                else:
                    target = connection.execute(
                        "SELECT * FROM plans WHERE plan_id=? AND version=?",
                        (row["plan_id"], target_version),
                    ).fetchone()
                    if target is None:
                        raise NotFoundError("指定的预案版本不存在")
                if target_version == row["plan_version"]:
                    raise ConflictError("事件已经使用该预案版本")
                plan = json.loads(target["payload_json"])
                facts = self._signal_aggregate_facts(connection, incident_id)
                aggregate = aggregate_signals(facts)
                shared_supply = bool(aggregate["shared_supply_codes"])
                classification = classify(aggregate["org_count"], aggregate["max_severity"], shared_supply)
                level = resolve_level(plan["escalation_rule"], classification,
                                      aggregate["max_severity"], aggregate["org_count"])
                lead = row["lead_actor_id"] if row["lead_overridden"] else plan["lead_by_classification"][classification]
                minutes = int(plan["response_minutes_by_level"][str(level)])
                due_at = self._iso(self._parse_ts(row["created_at"]) + timedelta(minutes=minutes))
                connection.execute(
                    "UPDATE incidents SET plan_version=?, classification=?, level=?, lead_actor_id=?, "
                    "response_due_at=?, version=version+1 WHERE incident_id=?",
                    (target_version, classification, level, lead, due_at, incident_id),
                )
                append_event(connection, actor_id=actor_id, action="incident.plan_adopted",
                             resource_type="incident", resource_id=incident_id,
                             detail={"from_version": row["plan_version"], "to_version": target_version,
                                     "classification": classification, "level": level,
                                     "lead_actor_id": lead}, occurred_at=self._now())
                return "incident", incident_id, {"incident_id": incident_id,
                                                 "plan_version": target_version, "level": level,
                                                 "classification": classification, "lead_actor_id": lead}

            return self._idempotent(connection, request_id=request_id,
                                    action="adopt_plan_version", payload=payload, create=create)

    # ------------------------------------------------------------------
    # 集群联防：可共享能力与带版本预占/确认
    # ------------------------------------------------------------------

    def declare_capability(self, *, request_id: str, actor_id: str, kind: str, total_qty: int,
                           shared_qty: int, site_id: str | None = None) -> WriteReceipt:
        """企业声明可共享的备用设备或技术人员。"""

        kind = str(kind).strip()
        if kind not in CAPABILITY_KINDS:
            raise ValidationError("kind 必须是 equipment 或 technician")
        total_qty = self._qty(total_qty, "total_qty")
        shared_qty = self._qty(shared_qty, "shared_qty")
        if shared_qty > total_qty:
            raise ValidationError("共享数量不能超过总量")
        payload = {"actor_id": actor_id, "kind": kind, "total_qty": total_qty,
                   "shared_qty": shared_qty, "site_id": site_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            if site_id is not None:
                site = connection.execute(
                    "SELECT organization_id FROM sites WHERE site_id=?", (site_id,)
                ).fetchone()
                if site is None:
                    raise NotFoundError("场所不存在")
                if actor.organization_id != site["organization_id"] and actor.role != "admin":
                    raise PermissionDenied("不能在其他企业的场所上声明能力")

            def create() -> tuple[str, str, dict[str, Any]]:
                capability_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO capabilities(capability_id,owner_org_id,site_id,kind,total_qty,shared_qty,"
                    "reserved_qty,confirmed_qty,version,active,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,0,0,1,1,?,?)",
                    (capability_id, actor.organization_id, site_id, kind, total_qty, shared_qty,
                     actor.actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="capability.declared",
                             resource_type="capability", resource_id=capability_id,
                             detail={"owner_org_id": actor.organization_id, "kind": kind,
                                     "total_qty": total_qty, "shared_qty": shared_qty},
                             occurred_at=self._now())
                return "capability", capability_id, {"capability_id": capability_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="declare_capability", payload=payload, create=create)

    def _load_capability(self, connection, capability_id: str):
        row = connection.execute(
            "SELECT * FROM capabilities WHERE capability_id=?", (capability_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("共享能力不存在")
        if not row["active"]:
            raise ConflictError("共享能力已停用")
        return row

    def _check_capability_version(self, row, expected_version: Any) -> None:
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise ValidationError("expected_version 必须是整数")
        if expected_version != row["version"]:
            raise ConflictError(f"能力版本已变化：当前 {row['version']}，请求依据 {expected_version}")

    def _require_commander(self, connection, actor: Actor, incident_row) -> None:
        """资源预占/确认/释放：事件牵头人或街道指挥侧；审计员只读。"""

        if actor.actor_id == incident_row["lead_actor_id"] and actor.role != "auditor":
            return
        try:
            self._require_command_side(connection, actor)
        except PermissionDenied as exc:
            raise PermissionDenied("只有指挥人员可以协调资源") from exc

    def _require_command_side(self, connection, actor: Actor) -> None:
        """开启/关闭/调度等指挥写操作：平台管理、监管复核或街道指挥侧，审计员只读。"""

        if actor.role in ("admin", "reviewer"):
            return
        if actor.role == "operator":
            row = connection.execute(
                "SELECT regulator FROM organizations WHERE organization_id=?",
                (actor.organization_id,),
            ).fetchone()
            if row and row["regulator"]:
                return
        raise PermissionDenied("只有街道指挥人员可以执行该指挥动作")

    def reserve_capability(self, *, request_id: str, actor_id: str, incident_id: str,
                           capability_id: str, qty: int, expected_version: int) -> WriteReceipt:
        """指挥人员基于能力版本预占共享量；同事务完成插入与扣减。"""

        qty = self._qty(qty, "qty")
        if qty <= 0:
            raise ValidationError("qty 必须是正整数")
        payload = {"actor_id": actor_id, "incident_id": incident_id, "capability_id": capability_id,
                   "qty": qty, "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            incident_id = self._identifier(incident_id, "incident_id")
            capability_id = self._identifier(capability_id, "capability_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
                ).fetchone()
                if incident is None:
                    raise NotFoundError("事件不存在")
                if incident["status"] != "open":
                    raise ConflictError("事件已关闭，不能再预占能力")
                self._require_commander(connection, actor, incident)
                cap = self._load_capability(connection, capability_id)
                self._check_capability_version(cap, expected_version)
                available = cap["shared_qty"] - cap["reserved_qty"] - cap["confirmed_qty"]
                if qty > available:
                    raise ConflictError(f"可预占共享量不足：剩余 {available}，申请 {qty}")
                allocation_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO allocations(allocation_id,incident_id,capability_id,capability_version,qty,"
                    "confirmed_qty,released_qty,revoked_qty,status,version,request_id,reserved_by,reserved_at) "
                    "VALUES(?,?,?,?,?,0,0,0,'reserved',1,?,?,?)",
                    (allocation_id, incident_id, capability_id, cap["version"], qty,
                     request_id, actor_id, now),
                )
                connection.execute(
                    "UPDATE capabilities SET reserved_qty=reserved_qty+?, version=version+1 "
                    "WHERE capability_id=?",
                    (qty, capability_id),
                )
                append_event(connection, actor_id=actor_id, action="capability.reserved",
                             resource_type="allocation", resource_id=allocation_id,
                             detail={"incident_id": incident_id, "capability_id": capability_id,
                                     "qty": qty, "capability_version": cap["version"]},
                             occurred_at=now)
                return "allocation", allocation_id, {"allocation_id": allocation_id,
                                                      "capability_version": cap["version"] + 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="reserve_capability", payload=payload, create=create)

    def _allocation_status(self, confirmed: int, released: int, revoked: int, qty: int) -> str:
        outstanding = qty - confirmed - released - revoked
        if outstanding > 0:
            return "partially_confirmed" if confirmed > 0 else "reserved"
        if confirmed == 0:
            return "revoked" if revoked > 0 else "released"
        if released > 0 or revoked > 0:
            return "partially_confirmed"
        return "confirmed"

    def confirm_capability(self, *, request_id: str, actor_id: str, allocation_id: str,
                           qty: int, expected_version: int) -> WriteReceipt:
        """带预占版本确认调用：只允许确认尚未释放/撤回的预占量。"""

        qty = self._qty(qty, "qty")
        if qty <= 0:
            raise ValidationError("qty 必须是正整数")
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise ValidationError("expected_version 必须是整数")
        payload = {"actor_id": actor_id, "allocation_id": allocation_id, "qty": qty,
                   "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            allocation_id = self._identifier(allocation_id, "allocation_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                alloc = connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id=?", (allocation_id,)
                ).fetchone()
                if alloc is None:
                    raise NotFoundError("预占记录不存在")
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (alloc["incident_id"],)
                ).fetchone()
                self._require_commander(connection, actor, incident)
                if alloc["version"] != expected_version:
                    raise ConflictError(f"预占版本已变化：当前 {alloc['version']}，请求依据 {expected_version}")
                outstanding = (alloc["qty"] - alloc["confirmed_qty"]
                               - alloc["released_qty"] - alloc["revoked_qty"])
                if outstanding <= 0:
                    raise ConflictError("该预占已经全部处置完毕")
                if qty > outstanding:
                    raise ConflictError(f"可确认量不足：未处置 {outstanding}，申请确认 {qty}")
                now = self._now()
                new_confirmed = alloc["confirmed_qty"] + qty
                status = self._allocation_status(new_confirmed, alloc["released_qty"],
                                                 alloc["revoked_qty"], alloc["qty"])
                connection.execute(
                    "UPDATE allocations SET confirmed_qty=?, status=?, version=version+1, "
                    "confirmed_by=?, confirmed_at=? WHERE allocation_id=?",
                    (new_confirmed, status, actor_id, now, allocation_id),
                )
                connection.execute(
                    "UPDATE capabilities SET reserved_qty=reserved_qty-?, confirmed_qty=confirmed_qty+?, "
                    "version=version+1 WHERE capability_id=?",
                    (qty, qty, alloc["capability_id"]),
                )
                append_event(connection, actor_id=actor_id, action="capability.confirmed",
                             resource_type="allocation", resource_id=allocation_id,
                             detail={"capability_id": alloc["capability_id"], "qty": qty,
                                     "confirmed_qty": new_confirmed, "status": status},
                             occurred_at=now)
                return "allocation", allocation_id, {"allocation_id": allocation_id,
                                                      "status": status,
                                                      "allocation_version": alloc["version"] + 1,
                                                      "capability_version_after": self._cap_version_after(
                                                          connection, alloc["capability_id"])}

            return self._idempotent(connection, request_id=request_id,
                                    action="confirm_capability", payload=payload, create=create)

    def _cap_version_after(self, connection, capability_id: str) -> int:
        return connection.execute(
            "SELECT version FROM capabilities WHERE capability_id=?", (capability_id,)
        ).fetchone()["version"]

    def release_capability(self, *, request_id: str, actor_id: str, allocation_id: str,
                           qty: int, expected_version: int) -> WriteReceipt:
        """释放尚未确认的预占量，使能力账本恢复平衡。"""

        qty = self._qty(qty, "qty")
        if qty <= 0:
            raise ValidationError("qty 必须是正整数")
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise ValidationError("expected_version 必须是整数")
        payload = {"actor_id": actor_id, "allocation_id": allocation_id, "qty": qty,
                   "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            allocation_id = self._identifier(allocation_id, "allocation_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                alloc = connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id=?", (allocation_id,)
                ).fetchone()
                if alloc is None:
                    raise NotFoundError("预占记录不存在")
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (alloc["incident_id"],)
                ).fetchone()
                self._require_commander(connection, actor, incident)
                if alloc["version"] != expected_version:
                    raise ConflictError(f"预占版本已变化：当前 {alloc['version']}，请求依据 {expected_version}")
                outstanding = (alloc["qty"] - alloc["confirmed_qty"]
                               - alloc["released_qty"] - alloc["revoked_qty"])
                if qty > outstanding:
                    raise ConflictError(f"可释放量不足：未处置 {outstanding}，申请释放 {qty}")
                now = self._now()
                new_released = alloc["released_qty"] + qty
                status = self._allocation_status(alloc["confirmed_qty"], new_released,
                                                 alloc["revoked_qty"], alloc["qty"])
                connection.execute(
                    "UPDATE allocations SET released_qty=?, status=?, version=version+1 WHERE allocation_id=?",
                    (new_released, status, allocation_id),
                )
                connection.execute(
                    "UPDATE capabilities SET reserved_qty=reserved_qty-?, version=version+1 "
                    "WHERE capability_id=?",
                    (qty, alloc["capability_id"]),
                )
                append_event(connection, actor_id=actor_id, action="capability.released",
                             resource_type="allocation", resource_id=allocation_id,
                             detail={"capability_id": alloc["capability_id"], "qty": qty,
                                     "status": status}, occurred_at=now)
                return "allocation", allocation_id, {"allocation_id": allocation_id, "status": status,
                                                      "allocation_version": alloc["version"] + 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="release_capability", payload=payload, create=create)

    def withdraw_capability(self, *, request_id: str, actor_id: str, capability_id: str,
                            qty: int, expected_version: int) -> WriteReceipt:
        """企业撤回共享量：只影响尚未确认的部分，必要时同事务撤销未确认预占。"""

        qty = self._qty(qty, "qty")
        if qty <= 0:
            raise ValidationError("qty 必须是正整数")
        payload = {"actor_id": actor_id, "capability_id": capability_id, "qty": qty,
                   "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            capability_id = self._identifier(capability_id, "capability_id")

            def create() -> tuple[str, str, dict[str, Any]]:
                cap = self._load_capability(connection, capability_id)
                if actor.organization_id != cap["owner_org_id"] and actor.role != "admin":
                    raise PermissionDenied("只能撤回本企业声明的共享量")
                self._check_capability_version(cap, expected_version)
                removable = cap["shared_qty"] - cap["confirmed_qty"]
                if qty > removable:
                    raise ConflictError(f"已确认的共享量不能撤回：最多撤回 {removable}，申请 {qty}")
                now = self._now()
                free = cap["shared_qty"] - cap["reserved_qty"] - cap["confirmed_qty"]
                need = qty - free
                revoked_allocations: list[dict[str, Any]] = []
                if need > 0:
                    candidates = connection.execute(
                        "SELECT * FROM allocations WHERE capability_id=? AND status IN ('reserved',"
                        "'partially_confirmed') ORDER BY reserved_at, allocation_id",
                        (capability_id,),
                    ).fetchall()
                    for alloc in candidates:
                        if need <= 0:
                            break
                        outstanding = (alloc["qty"] - alloc["confirmed_qty"]
                                       - alloc["released_qty"] - alloc["revoked_qty"])
                        take = min(need, outstanding)
                        new_revoked = alloc["revoked_qty"] + take
                        status = self._allocation_status(alloc["confirmed_qty"],
                                                         alloc["released_qty"], new_revoked, alloc["qty"])
                        connection.execute(
                            "UPDATE allocations SET revoked_qty=?, status=?, version=version+1 "
                            "WHERE allocation_id=?",
                            (new_revoked, status, alloc["allocation_id"]),
                        )
                        need -= take
                        revoked_allocations.append({"allocation_id": alloc["allocation_id"], "qty": take,
                                                    "status": status})
                connection.execute(
                    "UPDATE capabilities SET shared_qty=shared_qty-?, reserved_qty=reserved_qty-?, "
                    "version=version+1 WHERE capability_id=?",
                    (qty, sum((item["qty"] for item in revoked_allocations), 0), capability_id),
                )
                append_event(connection, actor_id=actor_id, action="capability.withdrawn",
                             resource_type="capability", resource_id=capability_id,
                             detail={"qty": qty, "revoked_allocations": revoked_allocations,
                                     "shared_qty_after": cap["shared_qty"] - qty}, occurred_at=now)
                return "capability", capability_id, {"capability_id": capability_id, "qty_withdrawn": qty,
                                                      "revoked_allocations": revoked_allocations,
                                                      "capability_version": cap["version"] + 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="withdraw_capability", payload=payload, create=create)

    # ------------------------------------------------------------------
    # 集群联防：按角色裁剪的查询视图
    # ------------------------------------------------------------------

    def _load_incident(self, connection, incident_id: str):
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("事件不存在")
        return row

    def _load_signals(self, connection, incident_id: str) -> list[dict[str, Any]]:
        result = []
        rows = connection.execute(
            "SELECT sig.*, s.organization_id FROM incident_signals sig "
            "JOIN sites s ON s.site_id = sig.site_id "
            "WHERE sig.incident_id=? ORDER BY sig.created_at, sig.signal_id",
            (incident_id,),
        ).fetchall()
        for row in rows:
            reports = connection.execute(
                "SELECT reporter_actor_id, payload_hash, reported_at FROM signal_reports "
                "WHERE signal_id=? ORDER BY reported_at, rowid",
                (row["signal_id"],),
            ).fetchall()
            item = dict(row)
            item["reports"] = [dict(report) for report in reports]
            result.append(item)
        return result

    def _load_allocations(self, connection, incident_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT a.*, c.owner_org_id, c.kind FROM allocations a "
            "JOIN capabilities c ON c.capability_id = a.capability_id "
            "WHERE a.incident_id=? ORDER BY a.reserved_at, a.allocation_id",
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def incident_view(self, incident_id: str, actor_id: str) -> dict[str, Any]:
        """按角色裁剪事件视图：参与方看自身责任与聚合态势，监管看完整来源。"""

        with self.database.transaction() as connection:
            viewer = self._actor(connection, actor_id)
            incident = self._load_incident(connection, incident_id)
            signals = self._load_signals(connection, incident_id)
            allocations = self._load_allocations(connection, incident_id)
            participant_orgs = {row["organization_id"] for row in signals}
            participant_orgs.update(row["owner_org_id"] for row in allocations)
            regulator = self._is_regulator_actor(connection, viewer)
            commander = viewer.actor_id == incident["lead_actor_id"]
            if not regulator and not commander and viewer.organization_id not in participant_orgs:
                raise PermissionDenied("无权查看该事件")
            return self._render_incident(incident, signals, allocations, viewer,
                                         regulator=regulator, commander=commander)

    def _render_incident(self, incident, signals: list[dict[str, Any]], allocations: list[dict[str, Any]],
                         viewer: Actor, *, regulator: bool, commander: bool) -> dict[str, Any]:
        active = [row for row in signals if not row["in_appendix"]]
        facts = aggregate_signals(active)
        view = {
            "incident_id": incident["incident_id"],
            "cluster_id": incident["cluster_id"],
            "signal_type": incident["signal_type"],
            "status": incident["status"],
            "version": incident["version"],
            "level": incident["level"],
            "classification": incident["classification"],
            "lead_actor_id": incident["lead_actor_id"],
            "lead_overridden": bool(incident["lead_overridden"]),
            "response_due_at": incident["response_due_at"],
            "created_at": incident["created_at"],
            "closed_at": incident["closed_at"],
            "plan": {"plan_id": incident["plan_id"], "plan_version": incident["plan_version"]},
            "aggregate": {
                "participant_org_count": facts["org_count"],
                "site_count": facts["site_count"],
                "signal_count": len(active),
                "report_count": sum(row["repeat_count"] for row in active),
                "max_severity": facts["max_severity"],
                "supply_codes": facts["supply_codes"],
                "shared_supply_codes": facts["shared_supply_codes"],
                "appendix_count": sum(1 for row in signals if row["in_appendix"]),
                "late_arrival_count": (sum(1 for row in signals if row["in_appendix"])
                                       + sum(row["late_count"] for row in signals)),
            },
        }
        full_sources = regulator or commander
        if full_sources:
            view["signals"] = [self._signal_full(row) for row in signals]
            view["allocations"] = [self._allocation_full(row) for row in allocations]
            return view
        peer_index: dict[str, str] = {}
        signal_views: list[dict[str, Any]] = []
        for row in signals:
            if row["organization_id"] == viewer.organization_id:
                signal_views.append(self._signal_full(row))
                continue
            label = peer_index.get(row["organization_id"])
            if label is None:
                label = f"peer-{len(peer_index) + 1}"
                peer_index[row["organization_id"]] = label
            signal_views.append({
                "participant": label,
                "severity": row["severity"],
                "supply_code": row["supply_code"],
                "occurred_at": row["occurred_at"],
                "repeat_count": row["repeat_count"],
                "in_appendix": bool(row["in_appendix"]),
            })
        view["signals"] = signal_views
        view["my_allocations"] = [
            self._allocation_full(row) for row in allocations
            if row["owner_org_id"] == viewer.organization_id
        ]
        posture: dict[str, dict[str, int]] = {}
        for row in allocations:
            bucket = posture.setdefault(row["kind"], {"requested": 0, "confirmed": 0,
                                                      "released": 0, "revoked": 0})
            bucket["requested"] += row["qty"]
            bucket["confirmed"] += row["confirmed_qty"]
            bucket["released"] += row["released_qty"]
            bucket["revoked"] += row["revoked_qty"]
        view["resource_posture"] = posture
        return view

    def _signal_full(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "signal_id": row["signal_id"],
            "site_id": row["site_id"],
            "organization_id": row["organization_id"],
            "fingerprint": row["fingerprint"],
            "severity": row["severity"],
            "supply_code": row["supply_code"],
            "payload": json.loads(row["payload_json"]),
            "occurred_at": row["occurred_at"],
            "repeat_count": row["repeat_count"],
            "in_appendix": bool(row["in_appendix"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "reports": row["reports"],
        }

    def _allocation_full(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "allocation_id": row["allocation_id"],
            "incident_id": row["incident_id"],
            "capability_id": row["capability_id"],
            "owner_org_id": row["owner_org_id"],
            "kind": row["kind"],
            "capability_version": row["capability_version"],
            "qty": row["qty"],
            "confirmed_qty": row["confirmed_qty"],
            "released_qty": row["released_qty"],
            "revoked_qty": row["revoked_qty"],
            "status": row["status"],
            "version": row["version"],
            "reserved_by": row["reserved_by"],
            "confirmed_by": row["confirmed_by"],
            "reserved_at": row["reserved_at"],
            "confirmed_at": row["confirmed_at"],
        }

    def list_incidents(self, actor_id: str, status: str | None = None) -> list[dict[str, Any]]:
        """列出当前角色可见的事件摘要。"""

        if status is not None and status not in ("open", "closed"):
            raise ValidationError("status 必须是 open 或 closed")
        with self.database.transaction() as connection:
            viewer = self._actor(connection, actor_id)
            query = "SELECT * FROM incidents"
            parameters: list[Any] = []
            if status:
                query += " WHERE status=?"
                parameters.append(status)
            query += " ORDER BY created_at, incident_id"
            items: list[dict[str, Any]] = []
            for row in connection.execute(query, parameters):
                signals = self._load_signals(connection, row["incident_id"])
                allocations = self._load_allocations(connection, row["incident_id"])
                participant_orgs = {item["organization_id"] for item in signals}
                participant_orgs.update(item["owner_org_id"] for item in allocations)
                regulator = self._is_regulator_actor(connection, viewer)
                commander = viewer.actor_id == row["lead_actor_id"]
                if not regulator and not commander and viewer.organization_id not in participant_orgs:
                    continue
                active = [item for item in signals if not item["in_appendix"]]
                facts = aggregate_signals(active)
                items.append({
                    "incident_id": row["incident_id"],
                    "cluster_id": row["cluster_id"],
                    "signal_type": row["signal_type"],
                    "status": row["status"],
                    "version": row["version"],
                    "level": row["level"],
                    "classification": row["classification"],
                    "lead_actor_id": row["lead_actor_id"],
                    "response_due_at": row["response_due_at"],
                    "created_at": row["created_at"],
                    "closed_at": row["closed_at"],
                    "participant_org_count": facts["org_count"],
                    "signal_count": len(active),
                    "report_count": sum(item["repeat_count"] for item in active),
                    "max_severity": facts["max_severity"],
                    "appendix_count": sum(1 for item in signals if item["in_appendix"]),
                    "involved": viewer.organization_id in participant_orgs or commander,
                })
            return items

    def list_capabilities(self, actor_id: str) -> dict[str, Any]:
        """列出共享能力：本企业完整、其他企业只给聚合可用性。"""

        with self.database.transaction() as connection:
            viewer = self._actor(connection, actor_id)
            rows = connection.execute(
                "SELECT * FROM capabilities WHERE active=1 ORDER BY created_at, capability_id"
            ).fetchall()
            own: list[dict[str, Any]] = []
            aggregates: dict[str, dict[str, int]] = {}
            full = self._is_regulator_actor(connection, viewer)
            all_items: list[dict[str, Any]] = []
            for row in rows:
                item = {
                    "capability_id": row["capability_id"],
                    "owner_org_id": row["owner_org_id"],
                    "site_id": row["site_id"],
                    "kind": row["kind"],
                    "total_qty": row["total_qty"],
                    "shared_qty": row["shared_qty"],
                    "reserved_qty": row["reserved_qty"],
                    "confirmed_qty": row["confirmed_qty"],
                    "available_qty": row["shared_qty"] - row["reserved_qty"] - row["confirmed_qty"],
                    "version": row["version"],
                }
                all_items.append(item)
                bucket = aggregates.setdefault(row["kind"], {"shared_qty": 0, "reserved_qty": 0,
                                                             "confirmed_qty": 0, "available_qty": 0,
                                                             "provider_count": 0})
                bucket["shared_qty"] += row["shared_qty"]
                bucket["reserved_qty"] += row["reserved_qty"]
                bucket["confirmed_qty"] += row["confirmed_qty"]
                bucket["available_qty"] += (row["shared_qty"] - row["reserved_qty"]
                                            - row["confirmed_qty"])
                bucket["provider_count"] += 1
            if full:
                return {"items": all_items, "aggregate": list(aggregates.values())}
            own = [item for item in all_items if item["owner_org_id"] == viewer.organization_id]
            summary = [{"kind": kind, **bucket} for kind, bucket in sorted(aggregates.items())]
            return {"my_capabilities": own, "cluster_aggregate": summary}

    def get_site(self, site_id: str) -> Site:
        row = self.database.connection.execute("SELECT * FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFoundError("场所不存在")
        keys = row.keys()
        cluster_id = row["cluster_id"] if "cluster_id" in keys else None
        return Site(row["site_id"], row["organization_id"], row["name"], row["timezone_name"],
                    row["version"], cluster_id)

    def list_domain_data(self, site_id: str, category: str | None = None) -> list[DomainRecord]:
        parameters: list[Any] = [site_id]
        query = "SELECT * FROM domain_records WHERE site_id=?"
        if category:
            query += " AND category=?"
            parameters.append(category)
        query += " ORDER BY created_at, record_id"
        records = []
        for row in self.database.connection.execute(query, parameters):
            records.append(DomainRecord(row["record_id"], row["site_id"], row["category"],
                                        row["external_key"], json.loads(row["payload_json"]),
                                        row["created_by"], row["created_at"]))
        return records

    def audit_events(self, after_sequence: int = 0) -> list[dict[str, Any]]:
        rows = self.database.connection.execute(
            "SELECT * FROM audit_events WHERE sequence>? ORDER BY sequence", (after_sequence,)
        ).fetchall()
        return [{"sequence": row["sequence"], "event_id": row["event_id"], "actor_id": row["actor_id"],
                 "action": row["action"], "resource_type": row["resource_type"],
                 "resource_id": row["resource_id"], "detail": json.loads(row["detail_json"]),
                 "previous_hash": row["previous_hash"], "event_hash": row["event_hash"],
                 "occurred_at": row["occurred_at"]} for row in rows]

    def verify_audit(self) -> tuple[bool, int]:
        return verify_chain(self.database.connection)
