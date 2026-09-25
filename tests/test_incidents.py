"""集群联防：信号归并、分级升级、附录与指挥链测试。"""

import unittest
from datetime import datetime, timezone

from cluster_response_core.clock import FixedClock
from cluster_response_core.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database


def build_service(clock=None):
    database = Database()
    service = DomainService(database, clock or FixedClock(datetime(2026, 9, 25, 8, tzinfo=timezone.utc)))
    service.register_organization(request_id="org-r", actor_id="bootstrap",
                                  organization_id="street", name="街道办", is_regulator=True)
    service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="adm",
                           display_name="管理员", role="admin", organization_id="street")
    service.register_actor(request_id="cmd", actor_id="adm", new_actor_id="cmd",
                           display_name="指挥员", role="operator", organization_id="street")
    service.register_actor(request_id="auditor", actor_id="adm", new_actor_id="au",
                           display_name="审计员", role="auditor", organization_id="street")
    for index, (oid, name) in enumerate([("o1", "家具一厂"), ("o2", "家具二厂"), ("o3", "家具三厂")], 1):
        service.register_organization(request_id=f"org-{oid}", actor_id="adm",
                                      organization_id=oid, name=name)
        service.register_actor(request_id=f"actor-{oid}", actor_id="adm", new_actor_id=f"e{index}",
                               display_name=f"{name}负责人", role="operator", organization_id=oid)
        service.register_site(request_id=f"site-{oid}", actor_id=f"e{index}", site_id=f"s{index}",
                              organization_id=oid, name=name, timezone_name="Asia/Shanghai",
                              cluster_id="cluster-a")
    return database, service


RULE = {"default_level": 1, "rules": [
    {"classification": "shared_supply", "level": 2},
    {"classification": "regional", "level": 3},
    {"min_orgs": 3, "level": 3},
    {"min_severity": "high", "level": 2},
]}
LEADS = {"single_fault": "cmd", "shared_supply": "cmd", "regional": "cmd"}
MINUTES = {"1": 120, "2": 60, "3": 30}


class IncidentFlowTest(unittest.TestCase):
    def setUp(self):
        self.database, self.service = build_service()

    def tearDown(self):
        self.database.close()

    def publish(self, request_id="plan-v1", rule=None):
        return self.service.publish_plan(
            request_id=request_id, actor_id="adm", plan_id="plan-a", cluster_id="cluster-a",
            escalation_rule=rule or RULE, lead_by_classification=LEADS,
            response_minutes_by_level=MINUTES)

    def test_plan_is_versioned_and_rejects_identical_republish(self):
        first = self.publish("p1")
        self.assertEqual("1", first.resource_id.rsplit(":", 1)[1])
        changed_rule = {"default_level": 2, "rules": [{"classification": "regional", "level": 3}]}
        second = self.publish("p2", rule=changed_rule)
        self.assertEqual("2", second.resource_id.rsplit(":", 1)[1])
        with self.assertRaises(ConflictError):
            self.publish("p3", rule=changed_rule)

    def test_plan_requires_lead_for_every_classification(self):
        with self.assertRaises(ValidationError):
            self.service.publish_plan(
                request_id="bad", actor_id="adm", plan_id="plan-b", cluster_id="cluster-a",
                escalation_rule=RULE, lead_by_classification={"single_fault": "cmd"},
                response_minutes_by_level=MINUTES)

    def test_single_fault_then_shared_supply_then_regional_escalation(self):
        self.publish()
        # 单厂先上报共用管路代码，此时仍是单厂故障
        receipt = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium", supply_code="manifold-7")
        incident_id = receipt.resource_id
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual("single_fault", view["classification"])
        self.assertEqual(1, view["level"])
        self.assertEqual("cmd", view["lead_actor_id"])
        self.assertEqual("2026-09-25T10:00:00Z", view["response_due_at"])

        # 第二家企业、相同共用供应代码 -> 共用供应异常，升级到 2 级（60 分钟）
        self.service.report_signal(
            request_id="sig-2", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-2", severity="medium", supply_code="manifold-7")
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual("shared_supply", view["classification"])
        self.assertEqual(2, view["level"])
        self.assertEqual(["manifold-7"], view["aggregate"]["shared_supply_codes"])
        self.assertEqual("2026-09-25T09:00:00Z", view["response_due_at"])

        # 第三家企业高严重度 -> 区域性风险，3 级（30 分钟）
        self.service.report_signal(
            request_id="sig-3", actor_id="e3", site_id="s3", signal_type="voc",
            fingerprint="fp-3", severity="high", supply_code="manifold-7")
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual("regional", view["classification"])
        self.assertEqual(3, view["level"])
        self.assertEqual("2026-09-25T08:30:00Z", view["response_due_at"])
        self.assertEqual(3, view["aggregate"]["participant_org_count"])

    def test_different_supply_codes_do_not_count_as_shared_supply(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium", supply_code="code-a").resource_id
        self.service.report_signal(
            request_id="sig-2", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-2", severity="medium", supply_code="code-b")
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual("single_fault", view["classification"])
        self.assertEqual([], view["aggregate"]["shared_supply_codes"])

    def test_duplicate_signal_merges_sources_without_new_signal(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        first_signal = self.service.report_signal(
            request_id="sig-1b", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium")
        second_signal = self.service.report_signal(
            request_id="sig-1c", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium")
        self.assertEqual(first_signal.resource_id, second_signal.resource_id)
        view = self.service.incident_view(incident_id, "au")
        self.assertEqual(1, len(view["signals"]))
        signal = view["signals"][0]
        self.assertEqual(3, signal["repeat_count"])
        self.assertEqual(3, len(signal["reports"]))
        self.assertEqual(3, view["aggregate"]["report_count"])

    def test_same_request_id_replays_receipt_without_doubling(self):
        self.publish()
        args = dict(actor_id="e1", site_id="s1", signal_type="voc",
                    fingerprint="fp-1", severity="medium")
        first = self.service.report_signal(request_id="idem", **args)
        replay = self.service.report_signal(request_id="idem", **args)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(first.resource_id, replay.resource_id)
        view = self.service.incident_view(first.resource_id, "au")
        self.assertEqual(1, view["aggregate"]["report_count"])

    def test_late_signals_enter_appendix_and_do_not_reopen(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="high").resource_id
        closed_level = self.service.incident_view(incident_id, "cmd")["level"]
        self.service.close_incident(request_id="close", actor_id="cmd", incident_id=incident_id)

        # 迟到的全新信号 -> 附录
        late = self.service.report_signal(
            request_id="late-1", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-x", severity="high", supply_code="manifold-7")
        # 迟到的重复信号也只进附录计数
        self.service.report_signal(
            request_id="late-2", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="high")
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual("closed", view["status"])
        self.assertEqual(closed_level, view["level"])
        self.assertEqual(2, view["aggregate"]["late_arrival_count"])
        self.assertEqual(1, view["aggregate"]["appendix_count"])
        self.assertTrue(all(s["in_appendix"] for s in view["signals"]
                            if s["signal_id"] == late.resource_id))

    def test_commander_opens_new_wave_after_closure(self):
        self.publish()
        old_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        self.service.close_incident(request_id="close", actor_id="cmd", incident_id=old_id)
        # 关闭后可以开启新一轮
        new_receipt = self.service.open_incident(
            request_id="wave-2", actor_id="cmd", cluster_id="cluster-a", signal_type="voc")
        self.assertNotEqual(old_id, new_receipt.resource_id)
        follow = self.service.report_signal(
            request_id="sig-2", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-2", severity="medium", supply_code="manifold-7")
        self.assertEqual(new_receipt.resource_id, follow.resource_id)
        # 同一告警类型同时只能有一个进行中事件
        with self.assertRaises(ConflictError):
            self.service.open_incident(request_id="wave-3", actor_id="cmd",
                                       cluster_id="cluster-a", signal_type="voc")

    def test_manual_lead_is_not_overwritten_by_reassessment(self):
        self.publish()
        self.service.register_actor(request_id="lead2", actor_id="adm", new_actor_id="cmd2",
                                    display_name="副指挥", role="operator", organization_id="street")
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        self.service.reassign_lead(request_id="reassign", actor_id="cmd",
                                   incident_id=incident_id, new_lead_actor_id="cmd2")
        self.service.report_signal(
            request_id="sig-2", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-2", severity="medium", supply_code="manifold-7")
        self.service.report_signal(
            request_id="sig-3", actor_id="e3", site_id="s3", signal_type="voc",
            fingerprint="fp-3", severity="high", supply_code="manifold-7")
        view = self.service.incident_view(incident_id, "au")
        self.assertEqual("cmd2", view["lead_actor_id"])
        self.assertTrue(view["lead_overridden"])

    def test_only_platform_admin_publishes_plan(self):
        with self.assertRaises(PermissionDenied):
            self.service.publish_plan(
                request_id="noperm", actor_id="e1", plan_id="plan-c", cluster_id="cluster-a",
                escalation_rule=RULE, lead_by_classification=LEADS,
                response_minutes_by_level=MINUTES)

    def test_enterprise_cannot_report_for_other_enterprise(self):
        self.publish()
        with self.assertRaises(PermissionDenied):
            self.service.report_signal(
                request_id="cross", actor_id="e1", site_id="s2", signal_type="voc",
                fingerprint="fp-z", severity="medium")

    def test_signal_payload_must_be_scalar_sanitized(self):
        self.publish()
        with self.assertRaises(ValidationError):
            self.service.report_signal(
                request_id="leak", actor_id="e1", site_id="s1", signal_type="voc",
                fingerprint="fp-s", severity="medium",
                payload={"production_log": ["secret", "data"]})

    def test_adopt_new_plan_version_recomputes_due_time(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        new_rule = {"default_level": 2, "rules": [{"classification": "regional", "level": 3}]}
        self.publish("plan-v2", rule=new_rule)
        receipt = self.service.adopt_plan_version(
            request_id="adopt", actor_id="cmd", incident_id=incident_id)
        self.assertFalse(receipt.replayed)
        self.assertEqual(incident_id, receipt.resource_id)
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual(2, view["plan"]["plan_version"])
        self.assertEqual(2, view["level"])
        self.assertEqual("2026-09-25T09:00:00Z", view["response_due_at"])

    def test_close_twice_conflicts(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        self.service.close_incident(request_id="c1", actor_id="cmd", incident_id=incident_id)
        with self.assertRaises(ConflictError):
            self.service.close_incident(request_id="c2", actor_id="cmd", incident_id=incident_id)
        with self.assertRaises(NotFoundError):
            self.service.close_incident(request_id="c3", actor_id="cmd", incident_id="missing-id")

    def test_auditor_is_read_only(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium").resource_id
        # 审计员可以追溯完整来源
        self.service.incident_view(incident_id, "au")
        for invocation in (
            lambda: self.service.close_incident(request_id="x1", actor_id="au",
                                                incident_id=incident_id),
            lambda: self.service.reassign_lead(request_id="x2", actor_id="au",
                                               incident_id=incident_id, new_lead_actor_id="cmd"),
            lambda: self.service.open_incident(request_id="x3", actor_id="au",
                                               cluster_id="cluster-a", signal_type="dust"),
            lambda: self.service.adopt_plan_version(request_id="x4", actor_id="au",
                                                    incident_id=incident_id),
        ):
            with self.assertRaises(PermissionDenied):
                invocation()

    def test_duplicate_signal_with_higher_severity_reassesses(self):
        self.publish()
        incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="low").resource_id
        self.assertEqual(1, self.service.incident_view(incident_id, "cmd")["level"])
        # 同指纹重复但严重度升至 high -> 命中 high 规则升到 2 级
        self.service.report_signal(
            request_id="sig-1b", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="high")
        view = self.service.incident_view(incident_id, "cmd")
        self.assertEqual(2, view["level"])
        self.assertEqual("high", view["aggregate"]["max_severity"])


if __name__ == "__main__":
    unittest.main()
