"""集群联防：跨企业查询字段裁剪、可见性与完整来源追溯测试。"""

import unittest
from datetime import datetime, timezone

from cluster_response_core.clock import FixedClock
from cluster_response_core.errors import PermissionDenied
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database

from tests.test_incidents import build_service, RULE, LEADS, MINUTES


class FieldFilteringTest(unittest.TestCase):
    def setUp(self):
        self.database, self.service = build_service()
        self.service.register_organization(request_id="org-o4", actor_id="adm",
                                           organization_id="o4", name="家具四厂")
        self.service.register_actor(request_id="actor-o4", actor_id="adm", new_actor_id="e4",
                                    display_name="四厂负责人", role="operator", organization_id="o4")
        self.service.publish_plan(request_id="plan", actor_id="adm", plan_id="plan-a",
                                  cluster_id="cluster-a", escalation_rule=RULE,
                                  lead_by_classification=LEADS, response_minutes_by_level=MINUTES)
        self.incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="medium", supply_code="manifold-7",
            payload={"reading": 0.41, "zone": "spray-booth"}).resource_id
        self.service.report_signal(
            request_id="sig-2", actor_id="e2", site_id="s2", signal_type="voc",
            fingerprint="fp-2", severity="high", supply_code="manifold-7",
            payload={"reading": 0.88})
        self.service.report_signal(
            request_id="sig-3", actor_id="e3", site_id="s3", signal_type="voc",
            fingerprint="fp-3", severity="medium", supply_code="manifold-7")
        self.cid = self.service.declare_capability(
            request_id="cap-1", actor_id="e1", kind="equipment", total_qty=4,
            shared_qty=3).resource_id
        self.cid2 = self.service.declare_capability(
            request_id="cap-2", actor_id="e2", kind="technician", total_qty=2,
            shared_qty=2).resource_id
        self.aid = self.service.reserve_capability(
            request_id="res", actor_id="cmd", incident_id=self.incident_id,
            capability_id=self.cid, qty=2, expected_version=1).resource_id
        self.service.confirm_capability(
            request_id="cf", actor_id="cmd", allocation_id=self.aid, qty=1, expected_version=1)

    def tearDown(self):
        self.database.close()

    def test_participant_sees_own_full_and_peers_anonymized(self):
        view = self.service.incident_view(self.incident_id, "e1")
        own = [s for s in view["signals"] if s.get("site_id") == "s1"]
        peers = [s for s in view["signals"] if s.get("site_id") != "s1"]
        self.assertEqual(1, len(own))
        self.assertIn("payload", own[0])
        self.assertEqual(0.41, own[0]["payload"]["reading"])
        self.assertEqual(2, len(peers))
        for peer in peers:
            # 其他企业的身份与敏感字段必须被裁剪
            self.assertNotIn("organization_id", peer)
            self.assertNotIn("site_id", peer)
            self.assertNotIn("fingerprint", peer)
            self.assertNotIn("payload", peer)
            self.assertTrue(peer["participant"].startswith("peer-"))
        # 参与方只能看到自己的能力预占明细
        self.assertEqual(1, len(view["my_allocations"]))
        self.assertEqual(self.aid, view["my_allocations"][0]["allocation_id"])
        self.assertNotIn("allocations", view)
        # 聚合资源态势可见，但不含提供方身份
        self.assertIn("equipment", view["resource_posture"])

    def test_participant_cannot_see_other_participant_allocation_detail(self):
        view = self.service.incident_view(self.incident_id, "e3")
        self.assertEqual([], view["my_allocations"])
        # 没有自身能力被调配时，仍可看到不带来源身份的聚合资源态势
        self.assertEqual(2, view["resource_posture"]["equipment"]["requested"])

    def test_commander_and_regulator_see_full_sources(self):
        for actor_id in ("cmd", "adm", "au"):
            view = self.service.incident_view(self.incident_id, actor_id)
            self.assertIn("allocations", view, f"{actor_id} 应看到完整调配明细")
            self.assertEqual(3, len(view["signals"]))
            for signal in view["signals"]:
                self.assertIn("organization_id", signal)
                self.assertIn("fingerprint", signal)
            self.assertEqual(1, len(view["allocations"]))

    def test_unrelated_enterprise_is_denied(self):
        with self.assertRaises(PermissionDenied):
            self.service.incident_view(self.incident_id, "e4")

    def test_capability_catalog_trims_provider_identity_for_enterprises(self):
        view = self.service.list_capabilities("e3")
        self.assertEqual([], view["my_capabilities"])
        kinds = {row["kind"]: row for row in view["cluster_aggregate"]}
        self.assertEqual(5, kinds["equipment"]["shared_qty"] + kinds["technician"]["shared_qty"])
        for row in view["cluster_aggregate"]:
            self.assertNotIn("capability_id", row)
            self.assertNotIn("owner_org_id", row)
        full = self.service.list_capabilities("cmd")
        self.assertIn("items", full)
        self.assertEqual(2, len(full["items"]))

    def test_list_incidents_visibility_and_summary(self):
        visible = {row["incident_id"] for row in self.service.list_incidents("e3")}
        self.assertIn(self.incident_id, visible)
        self.assertNotIn(self.incident_id,
                         {row["incident_id"] for row in self.service.list_incidents("e4")})
        summary = next(row for row in self.service.list_incidents("cmd")
                       if row["incident_id"] == self.incident_id)
        self.assertEqual(3, summary["participant_org_count"])
        self.assertEqual(3, summary["signal_count"])
        self.assertEqual("regional", summary["classification"])

    def test_regulator_can_trace_complete_sources(self):
        view = self.service.incident_view(self.incident_id, "au")
        signal = next(s for s in view["signals"] if s["site_id"] == "s1")
        self.assertEqual(1, len(signal["reports"]))
        self.assertIn("payload_hash", signal["reports"][0])
        self.assertEqual("e1", signal["reports"][0]["reporter_actor_id"])
        events = self.service.audit_events()
        actions = {event["action"] for event in events}
        self.assertIn("incident.opened", actions)
        self.assertIn("capability.reserved", actions)
        self.assertIn("capability.confirmed", actions)
        valid, _ = self.service.verify_audit()
        self.assertTrue(valid)

    def test_resource_posture_aggregates_without_owner_ids(self):
        view = self.service.incident_view(self.incident_id, "e2")
        posture = view["resource_posture"]
        self.assertEqual(2, posture["equipment"]["requested"])
        self.assertEqual(1, posture["equipment"]["confirmed"])


if __name__ == "__main__":
    unittest.main()
