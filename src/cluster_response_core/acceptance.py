"""运行基础服务与集群联防协同的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .joint_service import JointDefenseService
from .service import DomainService
from .storage import Database


def _run_base(service: DomainService) -> dict[str, object]:
    service.register_organization(request_id="req-org", actor_id="bootstrap",
                                  organization_id="org-001", name="示范企业")
    service.register_actor(request_id="req-admin", actor_id="bootstrap",
                           new_actor_id="admin-001", display_name="系统管理员",
                           role="admin", organization_id="org-001")
    service.register_actor(request_id="req-operator", actor_id="admin-001",
                           new_actor_id="operator-001", display_name="环保负责人",
                           role="operator", organization_id="org-001")
    service.register_site(request_id="req-site", actor_id="operator-001",
                          site_id="site-001", organization_id="org-001",
                          name="一号生产场所", timezone_name="Asia/Shanghai")
    first = service.record_domain_data(
        request_id="req-data", actor_id="operator-001", site_id="site-001",
        category="cluster_profile", external_key="record-001",
        data={"name": "基础资料", "enabled": True})
    replay = service.record_domain_data(
        request_id="req-data", actor_id="operator-001", site_id="site-001",
        category="cluster_profile", external_key="record-001",
        data={"name": "基础资料", "enabled": True})
    return {"first_replayed": first.replayed, "second_replayed": replay.replayed}


def _run_joint(base: DomainService, joint: JointDefenseService) -> dict[str, object]:
    """演练：多厂告警归并、升级、指挥链、原子预占确认与关闭后附录。"""

    base.register_organization(request_id="j-org-gov", actor_id="admin-001",
                               organization_id="org-street", name="示范街道")
    base.register_actor(request_id="j-admin", actor_id="admin-001", new_actor_id="j-admin",
                        display_name="街道管理员", role="admin",
                        organization_id="org-street")
    base.register_actor(request_id="j-commander", actor_id="j-admin",
                        new_actor_id="j-commander", display_name="现场指挥员",
                        role="operator", organization_id="org-street")
    base.register_actor(request_id="j-auditor", actor_id="j-admin", new_actor_id="j-auditor",
                        display_name="园区监管员", role="auditor",
                        organization_id="org-street")
    for index, org in enumerate(("org-plant-a", "org-plant-b"), start=1):
        base.register_organization(request_id=f"j-org-{index}", actor_id="j-admin",
                                   organization_id=org, name=f"家具企业{index}")
        base.register_actor(request_id=f"j-operator-{index}", actor_id="j-admin",
                            new_actor_id=f"j-operator-{index}",
                            display_name=f"企业{index}操作员", role="operator",
                            organization_id=org)
        base.register_site(request_id=f"j-site-{index}", actor_id=f"j-operator-{index}",
                           site_id=f"j-site-{index}", organization_id=org,
                           name=f"喷涂车间{index}", timezone_name="Asia/Shanghai")

    joint.publish_plan(
        request_id="j-plan-1", actor_id="j-admin", plan_id="voc-plan",
        name="园区废气治理联防预案",
        levels=[
            {"level": "L1", "rank": 1, "deadline_minutes": 60,
             "commander_role": "operator", "display_name": "企业自处置"},
            {"level": "L2", "rank": 2, "deadline_minutes": 30,
             "commander_role": "operator", "display_name": "园区联防"},
            {"level": "L3", "rank": 3, "deadline_minutes": 15,
             "commander_role": "admin", "display_name": "区域响应"},
        ],
        rules=[
            {"rule_id": "two-plants", "distinct_sources_min": 2,
             "max_severity_min": "medium", "set_level": "L2"},
        ],
        default_level="L1", group_keys=["park-001"], append_window_minutes=30)

    first = joint.report_signal(
        request_id="j-signal-1", actor_id="j-operator-1", group_key="park-001",
        signal_type="voc", severity="medium", dedup_key="alert-20260925-01",
        site_id="j-site-1")
    second = joint.report_signal(
        request_id="j-signal-2", actor_id="j-operator-2", group_key="park-001",
        signal_type="voc", severity="high", dedup_key="alert-20260925-01",
        site_id="j-site-2")
    incident_id = second.data["incident_id"]
    merged_and_escalated = second.data["merged"] and second.data["level"] == "L2"

    assignment = joint.assign_commander(
        request_id="j-assign", actor_id="j-admin", incident_id=incident_id,
        commander_actor_id="j-commander", reason="多厂同时告警，启动联防")

    joint.declare_capacity(
        request_id="j-cap-1", actor_id="j-operator-1", capacity_id="j-adsorber",
        resource_type="移动式活性炭吸附装置", total_qty=4, shared_qty=2,
        site_id="j-site-1")
    joint.declare_capacity(
        request_id="j-cap-2", actor_id="j-operator-2", capacity_id="j-technician",
        resource_type="废气治理技术员", total_qty=3, shared_qty=2)
    reserved = joint.reserve_capacities(
        request_id="j-reserve", actor_id="j-commander", incident_id=incident_id,
        requests=[{"capacity_id": "j-adsorber", "qty": 1, "expected_version": 1},
                  {"capacity_id": "j-technician", "qty": 1, "expected_version": 1}])
    allocation_ids = [item["allocation_id"] for item in reserved.data["allocations"]]
    confirmed = joint.confirm_allocations(
        request_id="j-confirm", actor_id="j-commander", incident_id=incident_id,
        allocation_ids=allocation_ids)

    # 参与企业看到责任与聚合态势，但看不到对方的身份明细。
    enterprise_view = joint.get_incident("j-operator-2", incident_id)
    enterprise_isolated = (
        "sources" not in enterprise_view["signals"][0]
        and "allocations" not in enterprise_view
        and enterprise_view["signals"][0]["other_sources"]["distinct_organizations"] == 1
    )
    # 监管人员可追溯完整来源。
    regulator_view = joint.get_incident("j-auditor", incident_id)
    full_provenance = len(regulator_view["signals"][0]["sources"]) == 2

    joint.close_incident(request_id="j-close", actor_id="j-commander",
                         incident_id=incident_id, note="告警消除，设备归位")
    late = joint.report_signal(
        request_id="j-late", actor_id="j-operator-1", group_key="park-001",
        signal_type="voc", severity="low", dedup_key="late-appendix",
        site_id="j-site-1")
    closed_view = joint.get_incident("j-auditor", incident_id)

    return {
        "incident_opened": first.data["new_incident"],
        "merged_and_escalated": merged_and_escalated,
        "commander_version": assignment.data["commander_version"],
        "reserved_count": len(allocation_ids),
        "confirmed_count": sum(1 for item in confirmed.data["allocations"]
                               if item["status"] == "confirmed"),
        "enterprise_field_isolation": enterprise_isolated,
        "regulator_full_provenance": full_provenance,
        "late_signal_phase": late.data["phase"],
        "terminal_untouched": closed_view["status"] == "closed",
        "appendix_count": closed_view["aggregate"]["appendix_signal_count"],
    }


def run() -> dict[str, object]:
    """执行完整登记链与联防演练并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        clock = FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))
        service = DomainService(database, clock)
        base_result = _run_base(service)
        joint = JointDefenseService(database, clock)
        joint_result = _run_joint(service, joint)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, **base_result, "joint_defense": joint_result}
        expected_flags = ("incident_opened", "merged_and_escalated",
                          "enterprise_field_isolation", "regulator_full_provenance",
                          "terminal_untouched")
        if not all(joint_result[name] for name in expected_flags):
            result["status"] = "joint_defense_failed"
        if joint_result["late_signal_phase"] != "appendix" \
                or joint_result["appendix_count"] != 1 \
                or joint_result["confirmed_count"] != 2 \
                or joint_result["commander_version"] != 1:
            result["status"] = "joint_defense_failed"
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
