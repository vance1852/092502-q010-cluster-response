"""实现集群联防协同：信号归并、版本化预案、指挥链与备用能力协同。"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .joint_models import ResponseLevel, ResponsePlan
from .models import Actor, WriteReceipt
from .storage import Database


SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
PHASE_LIVE = "live"
PHASE_APPENDIX = "appendix"

COMMAND_ROLES = ("admin", "operator")


class CommandResult:
    """一次幂等写命令的回执与业务结果。"""

    def __init__(self, receipt: WriteReceipt, data: dict[str, Any]) -> None:
        self.receipt = receipt
        self.data = data

    def as_dict(self) -> dict[str, Any]:
        return {"receipt": self.receipt.__dict__, "result": self.data}


class JointDefenseService:
    """协调脱敏信号、版本预案、唯一指挥链与原子资源预占。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _deadline(self, minutes: int) -> str:
        return (self.clock.now() + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

    def _integer(self, value: Any, field: str, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{field} 必须是整数")
        if value < minimum:
            raise ValidationError(f"{field} 不能小于 {minimum}")
        return value

    def _severity(self, value: Any) -> str:
        if value not in SEVERITY_RANK:
            raise ValidationError("severity 必须是 low/medium/high/critical")
        return value

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"],
                      row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _site_organization(self, connection, site_id: str) -> str:
        row = connection.execute("SELECT organization_id FROM sites WHERE site_id=?", (site_id,)).fetchone()
        if row is None:
            raise NotFoundError("场所不存在")
        return row["organization_id"]

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any], resource_type: str,
                    create: Callable[[], tuple[str, dict[str, Any]]]) -> CommandResult:
        request_id = str(request_id).strip()
        if not request_id or len(request_id) > 128:
            raise ValidationError("request_id 不能为空且不能超过 128 个字符")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return CommandResult(
                WriteReceipt(request_id, row["resource_type"], row["resource_id"], True),
                json.loads(row["response_json"]),
            )
        resource_id, data = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(data), self._now()),
        )
        return CommandResult(
            WriteReceipt(request_id, resource_type, resource_id, False), data
        )

    # ------------------------------------------------------------------
    # 版本化预案
    # ------------------------------------------------------------------

    def _parse_levels(self, raw: Any) -> tuple[ResponseLevel, ...]:
        if not isinstance(raw, list) or not raw:
            raise ValidationError("levels 必须是非空数组")
        levels: list[ResponseLevel] = []
        seen_names: set[str] = set()
        seen_ranks: set[int] = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValidationError("level 必须是对象")
            name = str(item.get("level", "")).strip()
            if not name or len(name) > 32 or name in seen_names:
                raise ValidationError("level 名称为空或重复")
            rank = self._integer(item.get("rank"), "level.rank", 0)
            if rank in seen_ranks:
                raise ValidationError("level.rank 不能重复")
            minutes = self._integer(item.get("deadline_minutes"), "level.deadline_minutes", 1)
            role = str(item.get("commander_role", "")).strip()
            if role not in COMMAND_ROLES:
                raise ValidationError("commander_role 必须是 admin 或 operator")
            display_name = str(item.get("display_name", name)).strip()[:80]
            levels.append(ResponseLevel(name, rank, minutes, role, display_name))
            seen_names.add(name)
            seen_ranks.add(rank)
        return tuple(sorted(levels, key=lambda level: level.rank))

    def _parse_rules(self, raw: Any, levels: tuple[ResponseLevel, ...]) -> tuple[dict[str, Any], ...]:
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise ValidationError("rules 必须是数组")
        level_names = {level.level for level in levels}
        rules: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                raise ValidationError("rule 必须是对象")
            rule_id = str(item.get("rule_id", "")).strip()
            if not rule_id or len(rule_id) > 64:
                raise ValidationError("rule_id 不能为空")
            set_level = str(item.get("set_level", "")).strip()
            if set_level not in level_names:
                raise ValidationError(f"规则 {rule_id} 引用了未定义的级别")
            min_sources = self._integer(item.get("distinct_sources_min", 1),
                                        "rule.distinct_sources_min", 1)
            min_severity = self._severity(item.get("max_severity_min", "low"))
            rules.append({"rule_id": rule_id, "distinct_sources_min": min_sources,
                          "max_severity_min": min_severity, "set_level": set_level})
        return tuple(rules)

    def publish_plan(self, *, request_id: str, actor_id: str, plan_id: str, name: str,
                     levels: list[dict[str, Any]], rules: list[dict[str, Any]] | None = None,
                     default_level: str, group_keys: list[str] | None = None,
                     append_window_minutes: int = 1440, activate: bool = True) -> CommandResult:
        """发布一个新版本的预案；激活时同预案旧版本同时停用。"""

        append_window_minutes = self._integer(append_window_minutes,
                                              "append_window_minutes", 0)
        payload = {"actor_id": actor_id, "plan_id": plan_id, "name": name, "levels": levels,
                   "rules": rules, "default_level": default_level, "group_keys": group_keys,
                   "append_window_minutes": append_window_minutes, "activate": activate}
        parsed_levels = self._parse_levels(levels)
        parsed_rules = self._parse_rules(rules, parsed_levels)
        if default_level not in {level.level for level in parsed_levels}:
            raise ValidationError("default_level 未在 levels 中定义")
        plan_id = str(plan_id).strip()
        if not plan_id or len(plan_id) > 64:
            raise ValidationError("plan_id 不能为空且不能超过 64 个字符")
        name = str(name).strip()
        if not name or len(name) > 120:
            raise ValidationError("name 不能为空且不能超过 120 个字符")
        groups = tuple(str(key).strip() for key in (group_keys or []))
        if any(not key or len(key) > 64 for key in groups):
            raise ValidationError("group_keys 含空值或超长值")

        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor.role != "admin":
                raise PermissionDenied("只有管理员可以发布预案")
            version_row = connection.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS version FROM response_plans WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            version = version_row["version"]

            def create() -> tuple[str, dict[str, Any]]:
                if activate:
                    connection.execute(
                        "UPDATE response_plans SET active=0 WHERE plan_id=?", (plan_id,)
                    )
                connection.execute(
                    "INSERT INTO response_plans(plan_id,version,name,levels_json,rules_json,"
                    "default_level,group_keys_csv,append_window_minutes,active,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (plan_id, version, name, canonical_json([level.__dict__ for level in parsed_levels]),
                     canonical_json(parsed_rules), default_level, ",".join(groups),
                     append_window_minutes, 1 if activate else 0, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="plan.published",
                             resource_type="response_plan",
                             resource_id=f"{plan_id}:{version}",
                             detail={"plan_id": plan_id, "version": version, "name": name,
                                     "activated": bool(activate), "group_keys": list(groups),
                                     "default_level": default_level},
                             occurred_at=self._now())
                return f"{plan_id}:{version}", {"plan_id": plan_id, "version": version,
                                                "active": bool(activate)}

            return self._idempotent(connection, request_id=request_id, action="publish_plan",
                                    payload=payload, resource_type="response_plan", create=create)

    def _load_plan(self, connection, plan_id: str, version: int) -> ResponsePlan:
        row = connection.execute(
            "SELECT * FROM response_plans WHERE plan_id=? AND version=?", (plan_id, version)
        ).fetchone()
        if row is None:
            raise NotFoundError("预案版本不存在")
        levels = tuple(ResponseLevel(**item) for item in json.loads(row["levels_json"]))
        return ResponsePlan(row["plan_id"], row["version"], row["name"], levels,
                            tuple(json.loads(row["rules_json"])), row["default_level"],
                            row["append_window_minutes"], bool(row["active"]),
                            row["created_by"], row["created_at"])

    def _active_plan_for_group(self, connection, group_key: str) -> ResponsePlan:
        """显式覆盖该集群的激活预案优先，否则取最近发布的通用预案。"""

        row = connection.execute(
            "SELECT plan_id, version FROM response_plans WHERE active=1 AND "
            "instr(','||group_keys_csv||',', ?) > 0 "
            "ORDER BY created_at DESC, version DESC LIMIT 1",
            (f",{group_key},",),
        ).fetchone()
        if row is None:
            row = connection.execute(
                "SELECT plan_id, version FROM response_plans "
                "WHERE active=1 AND group_keys_csv='' "
                "ORDER BY created_at DESC, version DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise NotFoundError("当前没有适用于该集群的激活预案")
        return self._load_plan(connection, row["plan_id"], row["version"])

    def get_plan(self, plan_id: str, version: int | None = None) -> ResponsePlan:
        """读取指定版本（缺省读取最新版本）的预案。"""

        connection = self.database.connection
        if version is None:
            row = connection.execute(
                "SELECT MAX(version) AS version FROM response_plans WHERE plan_id=?", (plan_id,)
            ).fetchone()
            if row["version"] is None:
                raise NotFoundError("预案不存在")
            version = row["version"]
        return self._load_plan(connection, plan_id, version)

    # ------------------------------------------------------------------
    # 信号归并与事件
    # ------------------------------------------------------------------

    def _aggregate_live(self, connection, incident_id: str) -> tuple[int, str]:
        """统计生效信号覆盖的不同企业数与最高严重度。"""

        row = connection.execute(
            "SELECT COUNT(DISTINCT s.organization_id) AS org_count, "
            "COALESCE(MAX(CASE s.severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 1 ELSE 0 END), 0) AS severity_rank "
            "FROM signal_sources s JOIN incident_signals i ON s.signal_id=i.signal_id "
            "WHERE i.incident_id=? AND s.phase=?",
            (incident_id, PHASE_LIVE),
        ).fetchone()
        return row["org_count"], SEVERITIES[row["severity_rank"]] if row["org_count"] else "low"

    def _evaluate_level(self, plan: ResponsePlan, distinct_orgs: int,
                        max_severity: str) -> tuple[str, str | None]:
        """按预案规则返回最高适用级别及触发规则编号。"""

        chosen = plan.default_level
        chosen_rule: str | None = None
        for rule in plan.rules:
            if (distinct_orgs >= rule["distinct_sources_min"]
                    and SEVERITY_RANK[max_severity] >= SEVERITY_RANK[rule["max_severity_min"]]):
                target = plan.level_by_name(rule["set_level"])
                current = plan.level_by_name(chosen)
                if target and (current is None or target.rank > current.rank):
                    chosen = rule["set_level"]
                    chosen_rule = rule["rule_id"]
        return chosen, chosen_rule

    def _append_signal(self, connection, *, actor, now: str, incident_row, phase: str,
                       group_key: str, signal_type: str, severity: str, dedup_key: str,
                       site_id: str, owner_org: str) -> tuple[str, dict[str, Any]]:
        """把一条信号归入既有事件；live 阶段按绑定预案评估升级，appendix 阶段永不改终态。"""

        incident_id = incident_row["incident_id"]
        signal_row = connection.execute(
            "SELECT * FROM incident_signals WHERE incident_id=? AND dedup_key=? AND phase=?",
            (incident_id, dedup_key, phase),
        ).fetchone()
        merged = signal_row is not None
        if signal_row is None:
            signal_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO incident_signals(signal_id,incident_id,dedup_key,signal_type,"
                "max_severity,phase,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)",
                (signal_id, incident_id, dedup_key, signal_type, severity, phase, now, now),
            )
        else:
            signal_id = signal_row["signal_id"]
            highest = severity if SEVERITY_RANK[severity] > SEVERITY_RANK[signal_row["max_severity"]] \
                else signal_row["max_severity"]
            connection.execute(
                "UPDATE incident_signals SET max_severity=?, last_seen_at=? WHERE signal_id=?",
                (highest, now, signal_id),
            )

        source_row = connection.execute(
            "SELECT * FROM signal_sources WHERE signal_id=? AND site_id=?",
            (signal_id, site_id),
        ).fetchone()
        if source_row is None:
            connection.execute(
                "INSERT INTO signal_sources(signal_id,site_id,organization_id,severity,"
                "phase,report_count,first_reported_at,last_reported_at) "
                "VALUES(?,?,?,?,?,1,?,?)",
                (signal_id, site_id, owner_org, severity, phase, now, now),
            )
        else:
            highest = severity if SEVERITY_RANK[severity] > SEVERITY_RANK[source_row["severity"]] \
                else source_row["severity"]
            connection.execute(
                "UPDATE signal_sources SET report_count=report_count+1, severity=?, "
                "last_reported_at=? WHERE signal_id=? AND site_id=?",
                (highest, now, signal_id, site_id),
            )
        append_event(connection, actor_id=actor.actor_id,
                     action="signal.merged" if merged else "signal.reported",
                     resource_type="signal", resource_id=signal_id,
                     detail={"incident_id": incident_id, "dedup_key": dedup_key,
                             "phase": phase, "site_id": site_id,
                             "organization_id": owner_org, "severity": severity,
                             "merged": merged},
                     occurred_at=now)

        escalated: dict[str, Any] | None = None
        resulting_level = incident_row["level"]
        if phase == PHASE_LIVE:
            plan = self._load_plan(connection, incident_row["plan_id"],
                                   incident_row["plan_version"])
            distinct_orgs, max_severity = self._aggregate_live(connection, incident_id)
            candidate, rule_id = self._evaluate_level(plan, distinct_orgs, max_severity)
            current_level = plan.level_by_name(incident_row["level"])
            target_level = plan.level_by_name(candidate)
            if target_level and (current_level is None or target_level.rank > current_level.rank):
                deadline = self._deadline(target_level.deadline_minutes)
                connection.execute(
                    "UPDATE incidents SET level=?, deadline_at=? WHERE incident_id=?",
                    (candidate, deadline, incident_id),
                )
                escalated = {"from_level": incident_row["level"], "to_level": candidate,
                             "rule_id": rule_id, "deadline_at": deadline}
                resulting_level = candidate
                append_event(connection, actor_id=actor.actor_id,
                             action="incident.level_escalated",
                             resource_type="incident", resource_id=incident_id,
                             detail=escalated, occurred_at=now)

        return incident_id, {"incident_id": incident_id, "phase": phase, "merged": merged,
                             "level": resulting_level, "escalated": escalated,
                             "new_incident": False}

    def report_signal(self, *, request_id: str, actor_id: str, group_key: str,
                      signal_type: str, severity: str, dedup_key: str,
                      site_id: str) -> CommandResult:
        """上报一条脱敏风险信号；重复信号合并来源，关闭事件后进入附录。"""

        severity = self._severity(severity)
        group_key = str(group_key).strip()
        signal_type = str(signal_type).strip()
        dedup_key = str(dedup_key).strip()
        if not group_key or len(group_key) > 64:
            raise ValidationError("group_key 不能为空且不能超过 64 个字符")
        if not signal_type or len(signal_type) > 64:
            raise ValidationError("signal_type 不能为空且不能超过 64 个字符")
        if not dedup_key or len(dedup_key) > 128:
            raise ValidationError("dedup_key 不能为空且不能超过 128 个字符")
        payload = {"actor_id": actor_id, "group_key": group_key, "signal_type": signal_type,
                   "severity": severity, "dedup_key": dedup_key, "site_id": site_id}

        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor.role not in ("admin", "operator", "reviewer"):
                raise PermissionDenied("当前角色不能上报信号")
            owner_org = self._site_organization(connection, site_id)
            if actor.organization_id != owner_org and actor.role != "admin":
                raise PermissionDenied("只能为所属企业的场所上报信号")
            now = self._now()

            def create() -> tuple[str, dict[str, Any]]:
                incident_row = connection.execute(
                    "SELECT * FROM incidents WHERE group_key=? AND signal_type=? "
                    "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    (group_key, signal_type),
                ).fetchone()

                # 已关闭事件：在绑定预案规定的附录窗口内归入附录；窗口外视为新一轮风险，开立新事件。
                if incident_row is not None and incident_row["status"] == "closed":
                    bound_plan = self._load_plan(connection, incident_row["plan_id"],
                                                 incident_row["plan_version"])
                    closed_at = datetime.fromisoformat(
                        incident_row["closed_at"].replace("Z", "+00:00"))
                    window_end = closed_at + timedelta(minutes=bound_plan.append_window_minutes)
                    if self.clock.now() <= window_end:
                        return self._append_signal(connection, actor=actor, now=now,
                                                   incident_row=incident_row,
                                                   phase=PHASE_APPENDIX, group_key=group_key,
                                                   signal_type=signal_type, severity=severity,
                                                   dedup_key=dedup_key, site_id=site_id,
                                                   owner_org=owner_org)
                    incident_row = None

                if incident_row is None:
                    plan = self._active_plan_for_group(connection, group_key)
                    incident_id = uuid.uuid4().hex
                    signal_id = uuid.uuid4().hex
                    level, _ = self._evaluate_level(plan, 1, severity)
                    level_obj = plan.level_by_name(level)
                    deadline = self._deadline(level_obj.deadline_minutes)
                    connection.execute(
                        "INSERT INTO incidents(incident_id,group_key,signal_type,plan_id,plan_version,"
                        "status,level,deadline_at,commander_actor_id,commander_version,note,created_at) "
                        "VALUES(?,?,?,?,?,'open',?,?,?,?,NULL,?)",
                        (incident_id, group_key, signal_type, plan.plan_id, plan.version,
                         level, deadline, None, 0, now),
                    )
                    connection.execute(
                        "INSERT INTO incident_signals(signal_id,incident_id,dedup_key,signal_type,"
                        "max_severity,phase,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)",
                        (signal_id, incident_id, dedup_key, signal_type, severity,
                         PHASE_LIVE, now, now),
                    )
                    connection.execute(
                        "INSERT INTO signal_sources(signal_id,site_id,organization_id,severity,"
                        "phase,report_count,first_reported_at,last_reported_at) "
                        "VALUES(?,?,?,?,?,1,?,?)",
                        (signal_id, site_id, owner_org, severity, PHASE_LIVE, now, now),
                    )
                    append_event(connection, actor_id=actor_id, action="incident.opened",
                                 resource_type="incident", resource_id=incident_id,
                                 detail={"group_key": group_key, "signal_type": signal_type,
                                         "plan_id": plan.plan_id, "plan_version": plan.version,
                                         "level": level, "deadline_at": deadline},
                                 occurred_at=now)
                    append_event(connection, actor_id=actor_id, action="signal.reported",
                                 resource_type="signal", resource_id=signal_id,
                                 detail={"incident_id": incident_id, "dedup_key": dedup_key,
                                         "phase": PHASE_LIVE, "site_id": site_id,
                                         "organization_id": owner_org, "severity": severity},
                                 occurred_at=now)
                    return incident_id, {"incident_id": incident_id, "phase": PHASE_LIVE,
                                         "merged": False, "level": level, "escalated": None,
                                         "new_incident": True}

                return self._append_signal(connection, actor=actor, now=now,
                                           incident_row=incident_row, phase=PHASE_LIVE,
                                           group_key=group_key, signal_type=signal_type,
                                           severity=severity, dedup_key=dedup_key,
                                           site_id=site_id, owner_org=owner_org)

            return self._idempotent(connection, request_id=request_id, action="report_signal",
                                    payload=payload, resource_type="incident", create=create)

    def withdraw_signal_source(self, *, request_id: str, actor_id: str, incident_id: str,
                               dedup_key: str, site_id: str) -> CommandResult:
        """企业撤回自己的一条信号来源；不自动降低事件级别。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "dedup_key": dedup_key, "site_id": site_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor.role not in ("admin", "operator", "reviewer"):
                raise PermissionDenied("当前角色不能撤回信号")
            owner_org = self._site_organization(connection, site_id)
            if actor.organization_id != owner_org and actor.role != "admin":
                raise PermissionDenied("只能撤回所属企业的信号来源")

            def create() -> tuple[str, dict[str, Any]]:
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
                ).fetchone()
                if incident is None:
                    raise NotFoundError("事件不存在")
                phase = PHASE_LIVE if incident["status"] == "open" else PHASE_APPENDIX
                signal = connection.execute(
                    "SELECT * FROM incident_signals WHERE incident_id=? AND dedup_key=? AND phase=?",
                    (incident_id, dedup_key, phase),
                ).fetchone()
                if signal is None:
                    raise NotFoundError("信号不存在")
                source = connection.execute(
                    "SELECT * FROM signal_sources WHERE signal_id=? AND site_id=?",
                    (signal["signal_id"], site_id),
                ).fetchone()
                if source is None:
                    raise NotFoundError("该场所没有此信号的上报来源")
                connection.execute(
                    "DELETE FROM signal_sources WHERE signal_id=? AND site_id=?",
                    (signal["signal_id"], site_id),
                )
                remaining = connection.execute(
                    "SELECT COUNT(*) AS count FROM signal_sources WHERE signal_id=?",
                    (signal["signal_id"],),
                ).fetchone()["count"]
                removed_signal = remaining == 0
                if removed_signal:
                    connection.execute(
                        "DELETE FROM incident_signals WHERE signal_id=?", (signal["signal_id"],)
                    )
                append_event(connection, actor_id=actor_id, action="signal.source_withdrawn",
                             resource_type="signal", resource_id=signal["signal_id"],
                             detail={"incident_id": incident_id, "dedup_key": dedup_key,
                                     "phase": phase, "site_id": site_id,
                                     "organization_id": owner_org,
                                     "signal_removed": removed_signal},
                             occurred_at=self._now())
                return incident_id, {"incident_id": incident_id, "phase": phase,
                                     "signal_removed": removed_signal}

            return self._idempotent(connection, request_id=request_id,
                                    action="withdraw_signal_source", payload=payload,
                                    resource_type="incident", create=create)

    # ------------------------------------------------------------------
    # 指挥链
    # ------------------------------------------------------------------

    def _load_incident(self, connection, incident_id: str):
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("事件不存在")
        return row

    def assign_commander(self, *, request_id: str, actor_id: str, incident_id: str,
                         commander_actor_id: str, reason: str | None = None,
                         expected_version: int | None = None) -> CommandResult:
        """按当前预案级别指定牵头人，带乐观版本维持唯一指挥链。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "commander_actor_id": commander_actor_id, "reason": reason,
                   "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor.role != "admin":
                raise PermissionDenied("只有管理员可以指定牵头人")
            incident = self._load_incident(connection, incident_id)
            if incident["status"] != "open":
                raise ConflictError("事件已关闭，不能变更指挥链")
            if expected_version is not None and incident["commander_version"] != expected_version:
                raise ConflictError("指挥链版本已变化，请刷新后重试")
            commander = self._actor(connection, commander_actor_id)
            plan = self._load_plan(connection, incident["plan_id"], incident["plan_version"])
            level = plan.level_by_name(incident["level"])
            if level and commander.role != level.commander_role:
                raise PermissionDenied(
                    f"预案 {plan.plan_id}:{plan.version} 的 {level.level} 级别要求牵头人角色为 "
                    f"{level.commander_role}"
                )

            def create() -> tuple[str, dict[str, Any]]:
                sequence = incident["commander_version"]
                connection.execute(
                    "UPDATE incidents SET commander_actor_id=?, commander_version=commander_version+1 "
                    "WHERE incident_id=?",
                    (commander_actor_id, incident_id),
                )
                connection.execute(
                    "INSERT INTO incident_command_history(incident_id,sequence,actor_id,reason,"
                    "assigned_by,assigned_at) VALUES(?,?,?,?,?,?)",
                    (incident_id, sequence, commander_actor_id, reason, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="incident.commander_assigned",
                             resource_type="incident", resource_id=incident_id,
                             detail={"commander_actor_id": commander_actor_id,
                                     "sequence": sequence, "reason": reason,
                                     "required_role": level.commander_role if level else None},
                             occurred_at=self._now())
                return incident_id, {"incident_id": incident_id,
                                     "commander_actor_id": commander_actor_id,
                                     "commander_version": sequence + 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="assign_commander", payload=payload,
                                    resource_type="incident", create=create)

    def _require_commander(self, connection, incident, actor: Actor) -> None:
        if actor.role not in COMMAND_ROLES:
            raise PermissionDenied("当前角色不能执行指挥动作")
        if not incident["commander_actor_id"]:
            raise ConflictError("事件尚未指定牵头人")
        if actor.actor_id != incident["commander_actor_id"]:
            raise PermissionDenied("只有当前牵头人可以执行该动作，指挥链必须唯一")
        # 升级后预案级别可能要求更高角色：现任牵头人不再满足时必须先由管理员重新指定。
        plan = self._load_plan(connection, incident["plan_id"], incident["plan_version"])
        level = plan.level_by_name(incident["level"])
        if level and actor.role != level.commander_role:
            raise PermissionDenied(
                f"事件已升级到 {level.level}，预案要求牵头人角色为 {level.commander_role}，"
                "请由管理员重新指定牵头人"
            )

    def close_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                       note: str | None = None) -> CommandResult:
        """关闭事件；此后到达的信号只进入附录。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._load_incident(connection, incident_id)
            self._require_commander(connection, incident, actor)

            def create() -> tuple[str, dict[str, Any]]:
                if incident["status"] != "open":
                    raise ConflictError("事件已经关闭")
                now = self._now()
                connection.execute(
                    "UPDATE incidents SET status='closed', closed_at=?, note=? WHERE incident_id=?",
                    (now, note, incident_id),
                )
                append_event(connection, actor_id=actor_id, action="incident.closed",
                             resource_type="incident", resource_id=incident_id,
                             detail={"closed_at": now, "note": note}, occurred_at=now)
                return incident_id, {"incident_id": incident_id, "closed_at": now}

            return self._idempotent(connection, request_id=request_id, action="close_incident",
                                    payload=payload, resource_type="incident", create=create)

    # ------------------------------------------------------------------
    # 备用能力声明、撤回与协同
    # ------------------------------------------------------------------

    def declare_capacity(self, *, request_id: str, actor_id: str, capacity_id: str,
                         resource_type: str, total_qty: int, shared_qty: int,
                         site_id: str | None = None) -> CommandResult:
        """企业声明可共享的备用能力（设备/人员）。"""

        total_qty = self._integer(total_qty, "total_qty", 0)
        shared_qty = self._integer(shared_qty, "shared_qty", 0)
        if shared_qty > total_qty:
            raise ValidationError("shared_qty 不能大于 total_qty")
        resource_type = str(resource_type).strip()
        if not resource_type or len(resource_type) > 64:
            raise ValidationError("resource_type 不能为空且不能超过 64 个字符")
        payload = {"actor_id": actor_id, "capacity_id": capacity_id, "resource_type": resource_type,
                   "total_qty": total_qty, "shared_qty": shared_qty, "site_id": site_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor.role not in ("admin", "operator"):
                raise PermissionDenied("当前角色不能声明备用能力")
            if site_id is not None:
                owner_org = self._site_organization(connection, site_id)
                if actor.organization_id != owner_org and actor.role != "admin":
                    raise PermissionDenied("不能把能力挂到其他企业的场所")
            else:
                owner_org = actor.organization_id

            def create() -> tuple[str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO standby_capacities(capacity_id,owner_organization_id,site_id,"
                        "resource_type,total_qty,shared_qty,active,version,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?,1,1,?,?)",
                        (capacity_id, owner_org, site_id, resource_type, total_qty, shared_qty,
                         actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("备用能力编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="capacity.declared",
                             resource_type="standby_capacity", resource_id=capacity_id,
                             detail={"owner_organization_id": owner_org, "site_id": site_id,
                                     "resource_type": resource_type, "total_qty": total_qty,
                                     "shared_qty": shared_qty},
                             occurred_at=self._now())
                return capacity_id, {"capacity_id": capacity_id, "version": 1,
                                     "shared_qty": shared_qty}

            return self._idempotent(connection, request_id=request_id, action="declare_capacity",
                                    payload=payload, resource_type="standby_capacity", create=create)

    def _held_quantities(self, connection, capacity_id: str) -> tuple[int, int]:
        """返回 (预占量, 已确认量)。"""

        row = connection.execute(
            "SELECT COALESCE(SUM(CASE WHEN status='reserved' THEN qty ELSE 0 END),0) AS reserved, "
            "COALESCE(SUM(CASE WHEN status='confirmed' THEN qty ELSE 0 END),0) AS confirmed "
            "FROM capacity_allocations WHERE capacity_id=? AND status IN ('reserved','confirmed')",
            (capacity_id,),
        ).fetchone()
        return row["reserved"], row["confirmed"]

    def update_capacity(self, *, request_id: str, actor_id: str, capacity_id: str,
                        total_qty: int, shared_qty: int, active: bool = True,
                        expected_version: int | None = None) -> CommandResult:
        """调整或撤回共享量；撤回只会驱逐尚未确认的预占，确认量受保护。"""

        total_qty = self._integer(total_qty, "total_qty", 0)
        shared_qty = self._integer(shared_qty, "shared_qty", 0)
        if shared_qty > total_qty:
            raise ValidationError("shared_qty 不能大于 total_qty")
        payload = {"actor_id": actor_id, "capacity_id": capacity_id, "total_qty": total_qty,
                   "shared_qty": shared_qty, "active": active, "expected_version": expected_version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            capacity = connection.execute(
                "SELECT * FROM standby_capacities WHERE capacity_id=?", (capacity_id,)
            ).fetchone()
            if capacity is None:
                raise NotFoundError("备用能力不存在")
            if actor.organization_id != capacity["owner_organization_id"] and actor.role != "admin":
                raise PermissionDenied("只能调整所属企业声明的备用能力")
            if actor.role not in ("admin", "operator"):
                raise PermissionDenied("当前角色不能调整备用能力")
            if expected_version is not None and capacity["version"] != expected_version:
                raise ConflictError("能力版本已变化，请刷新后重试")
            reserved, confirmed = self._held_quantities(connection, capacity_id)
            if shared_qty < confirmed:
                raise ConflictError(
                    f"共享量不能低于已确认量 {confirmed}：企业撤回只影响尚未确认的共享量"
                )

            def create() -> tuple[str, dict[str, Any]]:
                now = self._now()
                evicted: list[dict[str, Any]] = []
                held = reserved + confirmed
                if shared_qty < held:
                    # 按先预占先驱逐的顺序释放未确认预占；确认量绝不触碰。
                    rows = connection.execute(
                        "SELECT * FROM capacity_allocations WHERE capacity_id=? AND status='reserved' "
                        "ORDER BY created_at, allocation_id",
                        (capacity_id,),
                    ).fetchall()
                    for row in rows:
                        if held <= shared_qty:
                            break
                        connection.execute(
                            "UPDATE capacity_allocations SET status='released', "
                            "release_reason='capacity_withdrawn', version=version+1, updated_at=? "
                            "WHERE allocation_id=? AND status='reserved'",
                            (now, row["allocation_id"]),
                        )
                        held -= row["qty"]
                        evicted.append({"allocation_id": row["allocation_id"],
                                        "incident_id": row["incident_id"], "qty": row["qty"]})
                        append_event(connection, actor_id=actor_id, action="allocation.released",
                                     resource_type="allocation",
                                     resource_id=row["allocation_id"],
                                     detail={"capacity_id": capacity_id, "qty": row["qty"],
                                             "reason": "capacity_withdrawn",
                                             "incident_id": row["incident_id"]},
                                     occurred_at=now)
                    if held > shared_qty:
                        # 保护性分支：理论上由前面的确认量下限拦截，绝不留下不平衡扣减。
                        raise ConflictError("撤回后仍无法容纳已确认量，事务回滚")
                connection.execute(
                    "UPDATE standby_capacities SET total_qty=?, shared_qty=?, active=?, "
                    "version=version+1 WHERE capacity_id=?",
                    (total_qty, shared_qty, 1 if active else 0, capacity_id),
                )
                append_event(connection, actor_id=actor_id, action="capacity.updated",
                             resource_type="standby_capacity", resource_id=capacity_id,
                             detail={"total_qty": total_qty, "shared_qty": shared_qty,
                                     "active": active, "evicted_reservations": evicted,
                                     "previous_version": capacity["version"]},
                             occurred_at=now)
                return capacity_id, {"capacity_id": capacity_id, "version": capacity["version"] + 1,
                                     "shared_qty": shared_qty, "evicted": evicted}

            return self._idempotent(connection, request_id=request_id, action="update_capacity",
                                    payload=payload, resource_type="standby_capacity", create=create)

    def reserve_capacities(self, *, request_id: str, actor_id: str, incident_id: str,
                           requests: list[dict[str, Any]]) -> CommandResult:
        """指挥人员批量带版本预占；任一能力不足或版本不符则整体回滚。"""

        if not isinstance(requests, list) or not requests:
            raise ValidationError("requests 必须是非空数组")
        normalized: dict[str, tuple[int, int | None]] = {}
        for item in requests:
            if not isinstance(item, dict):
                raise ValidationError("预占项必须是对象")
            cap_id = str(item.get("capacity_id", "")).strip()
            qty = self._integer(item.get("qty"), "qty", 1)
            expected = item.get("expected_version")
            if expected is not None:
                expected = self._integer(expected, "expected_version", 1)
            if not cap_id:
                raise ValidationError("capacity_id 不能为空")
            if cap_id in normalized:
                aggregate_qty, aggregate_version = normalized[cap_id]
                qty = aggregate_qty + qty
                if expected is not None and aggregate_version is not None and expected != aggregate_version:
                    raise ValidationError(f"同一能力 {cap_id} 的版本要求不一致")
                expected = expected if expected is not None else aggregate_version
            normalized[cap_id] = (qty, expected)
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "requests": [{"capacity_id": key, "qty": value[0],
                                 "expected_version": value[1]}
                                for key, value in sorted(normalized.items())]}

        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._load_incident(connection, incident_id)
            self._require_commander(connection, incident, actor)
            if incident["status"] != "open":
                raise ConflictError("事件已关闭，不能再预占能力")

            # 预检全部通过后才写入，杜绝部分失败造成的不平衡扣减。
            plans: list[tuple[Any, int, int]] = []
            for cap_id, (qty, expected) in normalized.items():
                capacity = connection.execute(
                    "SELECT * FROM standby_capacities WHERE capacity_id=?", (cap_id,)
                ).fetchone()
                if capacity is None:
                    raise NotFoundError(f"备用能力 {cap_id} 不存在")
                if not capacity["active"]:
                    raise ConflictError(f"备用能力 {cap_id} 已停止共享")
                if expected is not None and capacity["version"] != expected:
                    raise ConflictError(f"备用能力 {cap_id} 版本已变化")
                reserved, confirmed = self._held_quantities(connection, cap_id)
                if reserved + confirmed + qty > capacity["shared_qty"]:
                    raise ConflictError(
                        f"备用能力 {cap_id} 可用量不足：需要 {qty}，"
                        f"可用 {capacity['shared_qty'] - reserved - confirmed}"
                    )
                plans.append((capacity, qty, reserved + confirmed))

            def create() -> tuple[str, dict[str, Any]]:
                now = self._now()
                results: list[dict[str, Any]] = []
                for capacity, qty, _held in plans:
                    allocation_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO capacity_allocations(allocation_id,incident_id,capacity_id,qty,"
                        "status,version,created_by,created_at,updated_at) "
                        "VALUES(?,?,?,?,'reserved',1,?,?,?)",
                        (allocation_id, incident_id, capacity["capacity_id"], qty, actor_id, now, now),
                    )
                    connection.execute(
                        "UPDATE standby_capacities SET version=version+1 WHERE capacity_id=?",
                        (capacity["capacity_id"],),
                    )
                    append_event(connection, actor_id=actor_id, action="allocation.reserved",
                                 resource_type="allocation", resource_id=allocation_id,
                                 detail={"incident_id": incident_id,
                                         "capacity_id": capacity["capacity_id"], "qty": qty,
                                         "capacity_version": capacity["version"] + 1},
                                 occurred_at=now)
                    results.append({"allocation_id": allocation_id,
                                    "capacity_id": capacity["capacity_id"], "qty": qty,
                                    "status": "reserved",
                                    "capacity_version": capacity["version"] + 1})
                return incident_id, {"incident_id": incident_id, "allocations": results}

            return self._idempotent(connection, request_id=request_id, action="reserve_capacities",
                                    payload=payload, resource_type="incident", create=create)

    def _bulk_allocation_action(self, *, request_id: str, actor_id: str, incident_id: str,
                                allocation_ids: list[str], action: str,
                                payload_extra: dict[str, Any] | None = None) -> CommandResult:
        if not isinstance(allocation_ids, list) or not allocation_ids:
            raise ValidationError("allocation_ids 必须是非空数组")
        if len(set(allocation_ids)) != len(allocation_ids):
            raise ValidationError("allocation_ids 不能重复")
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "allocation_ids": sorted(allocation_ids), "action": action}
        if payload_extra:
            payload.update(payload_extra)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            incident = self._load_incident(connection, incident_id)
            self._require_commander(connection, incident, actor)
            expected_versions = (payload_extra or {}).get("expected_versions", {})

            rows = []
            for allocation_id in allocation_ids:
                row = connection.execute(
                    "SELECT * FROM capacity_allocations WHERE allocation_id=?", (allocation_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"预占 {allocation_id} 不存在")
                if row["incident_id"] != incident_id:
                    raise PermissionDenied("不能跨事件操作预占记录")
                rows.append(row)
            if action == "confirm":
                for row in rows:
                    if row["status"] != "reserved":
                        raise ConflictError(f"预占 {row['allocation_id']} 状态为 {row['status']}，不能确认")
                    expected = expected_versions.get(row["allocation_id"])
                    if expected is not None and row["version"] != expected:
                        raise ConflictError(f"预占 {row['allocation_id']} 版本已变化")
                if incident["status"] != "open":
                    raise ConflictError("事件已关闭，不能确认预占")

            def create() -> tuple[str, dict[str, Any]]:
                now = self._now()
                results = []
                for row in rows:
                    if action == "confirm":
                        cursor = connection.execute(
                            "UPDATE capacity_allocations SET status='confirmed', version=version+1, "
                            "updated_at=? WHERE allocation_id=? AND status='reserved' AND version=?",
                            (now, row["allocation_id"], row["version"]),
                        )
                        new_status = "confirmed"
                        audit_action = "allocation.confirmed"
                    else:
                        if row["status"] not in ("reserved", "confirmed"):
                            raise ConflictError(
                                f"预占 {row['allocation_id']} 状态为 {row['status']}，不能释放"
                            )
                        cursor = connection.execute(
                            "UPDATE capacity_allocations SET status='released', "
                            "release_reason='commander_released', version=version+1, updated_at=? "
                            "WHERE allocation_id=? AND status IN ('reserved','confirmed') AND version=?",
                            (now, row["allocation_id"], row["version"]),
                        )
                        new_status = "released"
                        audit_action = "allocation.released"
                    if cursor.rowcount != 1:
                        # 并发下状态已被改动：整体回滚，绝不产生部分扣减。
                        raise ConflictError(f"预占 {row['allocation_id']} 并发冲突，整体回滚")
                    connection.execute(
                        "UPDATE standby_capacities SET version=version+1 WHERE capacity_id=?",
                        (row["capacity_id"],),
                    )
                    append_event(connection, actor_id=actor_id, action=audit_action,
                                 resource_type="allocation", resource_id=row["allocation_id"],
                                 detail={"incident_id": incident_id,
                                         "capacity_id": row["capacity_id"], "qty": row["qty"],
                                         "previous_version": row["version"]},
                                 occurred_at=now)
                    results.append({"allocation_id": row["allocation_id"],
                                    "capacity_id": row["capacity_id"], "qty": row["qty"],
                                    "status": new_status, "version": row["version"] + 1})
                return incident_id, {"incident_id": incident_id, "allocations": results}

            return self._idempotent(connection, request_id=request_id,
                                    action=f"{action}_allocations", payload=payload,
                                    resource_type="incident", create=create)

    def confirm_allocations(self, *, request_id: str, actor_id: str, incident_id: str,
                            allocation_ids: list[str],
                            expected_versions: dict[str, int] | None = None) -> CommandResult:
        """批量确认预占；并发或版本冲突时整体失败回滚。"""

        return self._bulk_allocation_action(
            request_id=request_id, actor_id=actor_id, incident_id=incident_id,
            allocation_ids=allocation_ids, action="confirm",
            payload_extra={"expected_versions": expected_versions or {}},
        )

    def release_allocations(self, *, request_id: str, actor_id: str, incident_id: str,
                            allocation_ids: list[str]) -> CommandResult:
        """批量释放预占或已确认量。"""

        return self._bulk_allocation_action(
            request_id=request_id, actor_id=actor_id, incident_id=incident_id,
            allocation_ids=allocation_ids, action="release",
        )

    # ------------------------------------------------------------------
    # 跨企业查询（按角色与归属裁剪字段）
    # ------------------------------------------------------------------

    def _signals_for_incident(self, connection, incident_id: str) -> list[dict[str, Any]]:
        signals: dict[str, dict[str, Any]] = {}
        signal_rows = connection.execute(
            "SELECT * FROM incident_signals WHERE incident_id=? ORDER BY first_seen_at, signal_id",
            (incident_id,),
        ).fetchall()
        for row in signal_rows:
            signals[row["signal_id"]] = {
                "signal_id": row["signal_id"], "dedup_key": row["dedup_key"],
                "signal_type": row["signal_type"], "max_severity": row["max_severity"],
                "phase": row["phase"], "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"], "sources": [],
            }
        source_rows = connection.execute(
            "SELECT * FROM signal_sources WHERE signal_id IN "
            "(SELECT signal_id FROM incident_signals WHERE incident_id=?) "
            "ORDER BY last_reported_at, site_id",
            (incident_id,),
        ).fetchall()
        for row in source_rows:
            signals[row["signal_id"]]["sources"].append(dict(row))
        return list(signals.values())

    def _participating_orgs(self, connection, incident_id: str) -> set[str]:
        return {row["organization_id"] for row in connection.execute(
            "SELECT DISTINCT s.organization_id FROM signal_sources s "
            "JOIN incident_signals i ON s.signal_id=i.signal_id WHERE i.incident_id=?",
            (incident_id,),
        ).fetchall()}

    def _trim_signals(self, signals: list[dict[str, Any]], *, full: bool,
                      viewer_org: str | None) -> list[dict[str, Any]]:
        """非监管视角只保留本企业来源，其他企业折叠为匿名聚合。"""

        trimmed = []
        for signal in signals:
            own_sources = [source for source in signal["sources"]
                           if source["organization_id"] == viewer_org]
            other_sources = [source for source in signal["sources"]
                             if source["organization_id"] != viewer_org]
            entry: dict[str, Any] = {
                "dedup_key": signal["dedup_key"], "signal_type": signal["signal_type"],
                "phase": signal["phase"], "max_severity": signal["max_severity"],
                "first_seen_at": signal["first_seen_at"], "last_seen_at": signal["last_seen_at"],
            }
            if full:
                entry["signal_id"] = signal["signal_id"]
                entry["sources"] = [{
                    "site_id": source["site_id"], "organization_id": source["organization_id"],
                    "severity": source["severity"], "phase": source["phase"],
                    "report_count": source["report_count"],
                    "first_reported_at": source["first_reported_at"],
                    "last_reported_at": source["last_reported_at"],
                } for source in signal["sources"]]
            else:
                entry["own_sources"] = [{
                    "site_id": source["site_id"], "severity": source["severity"],
                    "phase": source["phase"], "report_count": source["report_count"],
                    "first_reported_at": source["first_reported_at"],
                    "last_reported_at": source["last_reported_at"],
                } for source in own_sources]
                entry["other_sources"] = {
                    "count": len(other_sources),
                    "distinct_organizations": len({source["organization_id"]
                                                   for source in other_sources}),
                    "severity_breakdown": self._severity_breakdown(other_sources),
                    "reports": sum(source["report_count"] for source in other_sources),
                }
            trimmed.append(entry)
        return trimmed

    @staticmethod
    def _severity_breakdown(sources: list[dict[str, Any]]) -> dict[str, int]:
        breakdown = {name: 0 for name in SEVERITIES}
        for source in sources:
            breakdown[source["severity"]] += source["report_count"]
        return {key: value for key, value in breakdown.items() if value}

    def _allocations_for_incident(self, connection, incident_id: str) -> list[dict[str, Any]]:
        capacities = {row["capacity_id"]: dict(row) for row in connection.execute(
            "SELECT * FROM standby_capacities WHERE capacity_id IN "
            "(SELECT DISTINCT capacity_id FROM capacity_allocations WHERE incident_id=?)",
            (incident_id,),
        ).fetchall()}
        result = []
        for row in connection.execute(
            "SELECT * FROM capacity_allocations WHERE incident_id=? "
            "ORDER BY created_at, allocation_id", (incident_id,)
        ).fetchall():
            item = dict(row)
            item["owner_organization_id"] = capacities[row["capacity_id"]]["owner_organization_id"]
            item["resource_type"] = capacities[row["capacity_id"]]["resource_type"]
            result.append(item)
        return result

    def _visibility(self, connection, actor: Actor, incident_row,
                    participating: set[str] | None = None) -> tuple[bool, bool]:
        """返回 (是否可查看, 是否完整可见)；非参与企业直接拒绝。"""

        if participating is None:
            participating = self._participating_orgs(connection,
                                                     incident_row["incident_id"])
        is_commander = actor.actor_id == incident_row["commander_actor_id"]
        full_visibility = actor.role in ("admin", "auditor") or is_commander
        if actor.role not in ("admin", "auditor") \
                and actor.organization_id not in participating and not is_commander:
            raise PermissionDenied("企业只能查看自身参与的联防事件")
        return is_commander, full_visibility

    def _incident_view(self, connection, actor: Actor, incident_row) -> dict[str, Any]:
        incident_id = incident_row["incident_id"]
        plan = self._load_plan(connection, incident_row["plan_id"], incident_row["plan_version"])
        signals = self._signals_for_incident(connection, incident_id)
        live = [signal for signal in signals if signal["phase"] == PHASE_LIVE]
        appendix = [signal for signal in signals if signal["phase"] == PHASE_APPENDIX]
        allocations = self._allocations_for_incident(connection, incident_id)
        participating = self._participating_orgs(connection, incident_id)

        is_commander, full_visibility = self._visibility(connection, actor, incident_row,
                                                         participating)
        viewer_org = actor.organization_id

        live_sources = [source for signal in live for source in signal["sources"]]
        aggregate = {
            "distinct_organizations": len(participating),
            "live_signal_count": len(live),
            "live_source_count": len(live_sources),
            "appendix_signal_count": len(appendix),
            "appendix_source_count": sum(len(signal["sources"]) for signal in appendix),
            "severity_breakdown": self._severity_breakdown(live_sources),
            "confirmed_qty": sum(item["qty"] for item in allocations
                                 if item["status"] == "confirmed"),
            "reserved_qty": sum(item["qty"] for item in allocations
                                if item["status"] == "reserved"),
        }
        level_obj = plan.level_by_name(incident_row["level"])
        view = {
            "incident_id": incident_id, "group_key": incident_row["group_key"],
            "signal_type": incident_row["signal_type"], "status": incident_row["status"],
            "level": incident_row["level"],
            "level_display_name": level_obj.display_name if level_obj else incident_row["level"],
            "deadline_at": incident_row["deadline_at"],
            "commander_actor_id": incident_row["commander_actor_id"],
            "commander_version": incident_row["commander_version"],
            "plan_id": incident_row["plan_id"], "plan_version": incident_row["plan_version"],
            "plan_name": plan.name,
            "created_at": incident_row["created_at"], "closed_at": incident_row["closed_at"],
            "aggregate": aggregate,
            "signals": self._trim_signals(live, full=full_visibility, viewer_org=viewer_org),
            "appendix": self._trim_signals(appendix, full=full_visibility, viewer_org=viewer_org),
        }
        if full_visibility:
            view["note"] = incident_row["note"]
            view["allocations"] = [{
                "allocation_id": item["allocation_id"], "capacity_id": item["capacity_id"],
                "owner_organization_id": item["owner_organization_id"],
                "resource_type": item["resource_type"], "qty": item["qty"],
                "status": item["status"], "release_reason": item["release_reason"],
                "version": item["version"], "created_by": item["created_by"],
                "created_at": item["created_at"], "updated_at": item["updated_at"],
            } for item in allocations]
        else:
            view["own_allocations"] = [{
                "allocation_id": item["allocation_id"], "capacity_id": item["capacity_id"],
                "resource_type": item["resource_type"], "qty": item["qty"],
                "status": item["status"], "version": item["version"],
                "created_at": item["created_at"], "updated_at": item["updated_at"],
            } for item in allocations if item["owner_organization_id"] == viewer_org]
            view["responsibility"] = {
                "own_live_source_count": sum(
                    1 for signal in live for source in signal["sources"]
                    if source["organization_id"] == viewer_org),
                "own_confirmed_shared_qty": sum(
                    item["qty"] for item in allocations
                    if item["owner_organization_id"] == viewer_org
                    and item["status"] == "confirmed"),
                "own_reserved_shared_qty": sum(
                    item["qty"] for item in allocations
                    if item["owner_organization_id"] == viewer_org
                    and item["status"] == "reserved"),
            }
        return view

    def get_incident(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """按角色裁剪的事件视图：责任与聚合态势可见，完整来源仅监管侧可见。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            incident = self._load_incident(connection, incident_id)
            return self._incident_view(connection, actor, incident)

    def list_incidents(self, actor_id: str, status: str | None = None) -> dict[str, Any]:
        """列出事件摘要；企业只看到自身参与的事件。"""

        if status not in (None, "open", "closed"):
            raise ValidationError("status 必须是 open 或 closed")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            if actor.role in ("admin", "auditor"):
                sql = "SELECT * FROM incidents"
                params: list[Any] = []
                if status:
                    sql += " WHERE status=?"
                    params.append(status)
            else:
                sql = ("SELECT i.* FROM incidents i WHERE "
                       "i.incident_id IN (SELECT si.incident_id FROM signal_sources ss "
                       "JOIN incident_signals si ON ss.signal_id=si.signal_id "
                       "WHERE ss.organization_id=?) OR i.commander_actor_id=?")
                params = [actor.organization_id, actor.actor_id]
                if status:
                    sql += " AND i.status=?"
                    params.append(status)
            sql += " ORDER BY created_at, incident_id"
            rows = connection.execute(sql, params).fetchall()
            items = []
            for row in rows:
                plan = self._load_plan(connection, row["plan_id"], row["plan_version"])
                participating = self._participating_orgs(connection, row["incident_id"])
                is_commander = actor.actor_id == row["commander_actor_id"]
                live_sources = connection.execute(
                    "SELECT s.severity, s.report_count FROM signal_sources s "
                    "JOIN incident_signals i ON s.signal_id=i.signal_id "
                    "WHERE i.incident_id=? AND s.phase=?",
                    (row["incident_id"], PHASE_LIVE),
                ).fetchall()
                appendix_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM incident_signals WHERE incident_id=? AND phase=?",
                    (row["incident_id"], PHASE_APPENDIX),
                ).fetchone()["count"]
                items.append({
                    "incident_id": row["incident_id"], "group_key": row["group_key"],
                    "signal_type": row["signal_type"], "status": row["status"],
                    "level": row["level"],
                    "plan_id": row["plan_id"], "plan_version": row["plan_version"],
                    "deadline_at": row["deadline_at"],
                    "commander_actor_id": row["commander_actor_id"],
                    "is_my_command": is_commander,
                    "participating": actor.organization_id in participating
                    if actor.role not in ("admin", "auditor") else True,
                    "aggregate": {
                        "distinct_organizations": len(participating),
                        "severity_breakdown": self._severity_breakdown(
                            [dict(severity=row2["severity"], report_count=row2["report_count"])
                             for row2 in live_sources]),
                        "appendix_signal_count": appendix_count,
                    },
                })
            return {"items": items}

    def list_capacities(self, actor_id: str, *, include_inactive: bool = False) -> dict[str, Any]:
        """列出共享备用能力；非监管视角隐藏其他企业身份，只暴露共享目录。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            full_visibility = actor.role in ("admin", "auditor")
            sql = "SELECT * FROM standby_capacities"
            params: list[Any] = []
            if not full_visibility:
                sql += " WHERE owner_organization_id=? OR active=1"
                params.append(actor.organization_id)
            if not include_inactive:
                sql += " WHERE active=1" if full_visibility else " AND active=1"
            sql += " ORDER BY created_at, capacity_id"
            rows = connection.execute(sql, params).fetchall()
            items = []
            for row in rows:
                reserved, confirmed = self._held_quantities(connection, row["capacity_id"])
                is_own = row["owner_organization_id"] == actor.organization_id
                item = {
                    "capacity_id": row["capacity_id"], "resource_type": row["resource_type"],
                    "shared_qty": row["shared_qty"],
                    "reserved_qty": reserved, "confirmed_qty": confirmed,
                    "available_qty": row["shared_qty"] - reserved - confirmed,
                    "active": bool(row["active"]), "version": row["version"],
                }
                if full_visibility or is_own:
                    item["owner_organization_id"] = row["owner_organization_id"]
                    item["site_id"] = row["site_id"]
                    item["total_qty"] = row["total_qty"]
                else:
                    item["owner_organization_id"] = None
                    item["anonymous"] = True
                items.append(item)
            return {"items": items}

    def commander_chain(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """返回事件指挥链历史；可追溯性受与事件视图相同的参与边界约束。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if incident is None:
                raise NotFoundError("事件不存在")
            self._visibility(connection, actor, incident)
            history = connection.execute(
                "SELECT * FROM incident_command_history WHERE incident_id=? ORDER BY sequence",
                (incident_id,),
            ).fetchall()
            return {
                "incident_id": incident_id,
                "current_commander_actor_id": incident["commander_actor_id"],
                "commander_version": incident["commander_version"],
                "history": [{"sequence": row["sequence"], "actor_id": row["actor_id"],
                             "reason": row["reason"], "assigned_by": row["assigned_by"],
                             "assigned_at": row["assigned_at"]} for row in history],
            }
