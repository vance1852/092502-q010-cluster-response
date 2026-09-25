"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .service import DomainService
from .storage import Database


def _run_joint_defense(service: DomainService) -> dict[str, object]:
    """在同一库中走一遍集群联防：分级、预占确认、撤回、关闭附录与重启一致性。"""

    service.register_organization(request_id="jd-street", actor_id="admin-001",
                                  organization_id="jd-street", name="示范街道", is_regulator=True)
    service.register_actor(request_id="jd-admin", actor_id="admin-001", new_actor_id="jd-admin",
                           display_name="平台管理员", role="admin", organization_id="jd-street")
    service.register_actor(request_id="jd-cmd", actor_id="jd-admin", new_actor_id="jd-cmd",
                           display_name="值班指挥", role="operator", organization_id="jd-street")
    for index, oid in enumerate(("jd-f1", "jd-f2", "jd-f3"), 1):
        service.register_organization(request_id=f"jd-org-{index}", actor_id="jd-admin",
                                      organization_id=oid, name=f"家具{index}厂")
        service.register_actor(request_id=f"jd-actor-{index}", actor_id="jd-admin",
                               new_actor_id=f"jd-e{index}", display_name=f"家具{index}厂负责人",
                               role="operator", organization_id=oid)
        service.register_site(request_id=f"jd-site-{index}", actor_id=f"jd-e{index}",
                              site_id=f"jd-site-{index}", organization_id=oid,
                              name=f"{index}号车间", timezone_name="Asia/Shanghai",
                              cluster_id="jd-cluster")
    rule = {"default_level": 1, "rules": [
        {"classification": "shared_supply", "level": 2},
        {"classification": "regional", "level": 3},
    ]}
    leads = {"single_fault": "jd-cmd", "shared_supply": "jd-cmd", "regional": "jd-cmd"}
    service.publish_plan(request_id="jd-plan", actor_id="jd-admin", plan_id="jd-plan",
                         cluster_id="jd-cluster", escalation_rule=rule,
                         lead_by_classification=leads,
                         response_minutes_by_level={"1": 120, "2": 60, "3": 30})
    incident = service.report_signal(
        request_id="jd-sig-1", actor_id="jd-e1", site_id="jd-site-1", signal_type="voc",
        fingerprint="jd-fp-1", severity="medium", supply_code="共用管路7")
    incident_id = incident.resource_id
    service.report_signal(request_id="jd-sig-2", actor_id="jd-e2", site_id="jd-site-2",
                          signal_type="voc", fingerprint="jd-fp-2", severity="medium",
                          supply_code="共用管路7")
    service.report_signal(request_id="jd-sig-3", actor_id="jd-e3", site_id="jd-site-3",
                          signal_type="voc", fingerprint="jd-fp-3", severity="high",
                          supply_code="共用管路7")
    escalated = service.incident_view(incident_id, "jd-cmd")
    capability = service.declare_capability(
        request_id="jd-cap", actor_id="jd-e1", kind="equipment", total_qty=4, shared_qty=3)
    cap_id = capability.resource_id
    allocation = service.reserve_capability(
        request_id="jd-res", actor_id="jd-cmd", incident_id=incident_id,
        capability_id=cap_id, qty=2, expected_version=1)
    allocation_id = allocation.resource_id
    service.confirm_capability(request_id="jd-cf", actor_id="jd-cmd",
                               allocation_id=allocation_id, qty=1, expected_version=1)
    # 撤回 2：仅撤销未确认预占，已确认的 1 个保留
    service.withdraw_capability(request_id="jd-wd", actor_id="jd-e1",
                                capability_id=cap_id, qty=2, expected_version=3)
    service.close_incident(request_id="jd-close", actor_id="jd-cmd", incident_id=incident_id)
    service.report_signal(request_id="jd-late", actor_id="jd-e2", site_id="jd-site-2",
                          signal_type="voc", fingerprint="jd-fp-late", severity="high",
                          supply_code="共用管路7")
    closed = service.incident_view(incident_id, "jd-cmd")
    peer = service.incident_view(incident_id, "jd-e1")
    return {
        "joint_classification": escalated["classification"],
        "joint_level": escalated["level"],
        "joint_lead": escalated["lead_actor_id"],
        "joint_closed_status": closed["status"],
        "joint_appendix": closed["aggregate"]["appendix_count"],
        "joint_peer_sees_full_sources": any("organization_id" in s for s in peer["signals"]
                                            if s.get("site_id") != "jd-site-1"),
    }


def run() -> dict[str, object]:
    """执行一条完整登记链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = DomainService(database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范企业")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="环保负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号生产场所", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="cluster_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="cluster_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})
        joint = _run_joint_defense(service)
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed, **joint}
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    success = (result["status"] == "ok" and result["audit_valid"]
               and result["joint_classification"] == "regional"
               and result["joint_level"] == 3
               and result["joint_closed_status"] == "closed"
               and result["joint_appendix"] == 1
               and not result["joint_peer_sees_full_sources"])
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
