"""集群联防 HTTP 路由测试。"""

import unittest

from cluster_response_core.api import route
from cluster_response_core.errors import ConflictError
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database

RULE = {"default_level": 1, "rules": [
    {"classification": "shared_supply", "level": 2},
    {"classification": "regional", "level": 3},
]}
LEADS = {"single_fault": "cmd", "shared_supply": "cmd", "regional": "cmd"}
MINUTES = {"1": 120, "2": 60, "3": 30}


class JointDefenseApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)
        route(self.service, "POST", "/organizations",
              {"request_id": "org", "organization_id": "street", "name": "街道",
               "is_regulator": True}, {"X-Actor-Id": "bootstrap"})
        route(self.service, "POST", "/actors",
              {"request_id": "adm", "new_actor_id": "adm", "display_name": "管理员",
               "role": "admin", "organization_id": "street"}, {"X-Actor-Id": "bootstrap"})
        for aid, name, role in [("cmd", "指挥", "operator"), ("au", "审计", "auditor")]:
            route(self.service, "POST", "/actors",
                  {"request_id": aid, "new_actor_id": aid, "display_name": name,
                   "role": role, "organization_id": "street"}, {"X-Actor-Id": "adm"})
        route(self.service, "POST", "/organizations",
              {"request_id": "o1", "organization_id": "o1", "name": "家具一厂"},
              {"X-Actor-Id": "adm"})
        route(self.service, "POST", "/actors",
              {"request_id": "e1", "new_actor_id": "e1", "display_name": "厂负责人",
               "role": "operator", "organization_id": "o1"}, {"X-Actor-Id": "adm"})
        route(self.service, "POST", "/sites",
              {"request_id": "s1", "site_id": "site-1", "organization_id": "o1", "name": "车间",
               "timezone_name": "Asia/Shanghai", "cluster_id": "cluster-a"},
              {"X-Actor-Id": "e1"})
        status, plan = route(self.service, "POST", "/plans",
                             {"request_id": "plan", "plan_id": "plan-a", "cluster_id": "cluster-a",
                              "escalation_rule": RULE, "lead_by_classification": LEADS,
                              "response_minutes_by_level": MINUTES}, {"X-Actor-Id": "adm"})
        self.assertEqual(201, status)
        self.assertEqual("plan-a:1", plan["resource_id"])

    def tearDown(self):
        self.database.close()

    def test_full_joint_defense_flow_over_http(self):
        status, signal = route(self.service, "POST", "/signals",
                               {"request_id": "sig-1", "site_id": "site-1", "signal_type": "voc",
                                "fingerprint": "fp-1", "severity": "high",
                                "payload": {"reading": 0.9}}, {"X-Actor-Id": "e1"})
        self.assertEqual(201, status)
        incident_id = signal["resource_id"]

        status, view = route(self.service, "GET", f"/incidents/{incident_id}", None,
                             {"X-Actor-Id": "cmd"})
        self.assertEqual(200, status)
        self.assertEqual("single_fault", view["classification"])
        self.assertIn("aggregate", view)

        # 企业声明能力 -> 指挥预占 -> 确认
        status, cap = route(self.service, "POST", "/capabilities",
                            {"request_id": "cap", "kind": "equipment", "total_qty": 3,
                             "shared_qty": 2}, {"X-Actor-Id": "e1"})
        self.assertEqual(201, status)
        cid = cap["resource_id"]
        status, reserve = route(self.service, "POST", "/allocations/reserve",
                                {"request_id": "res", "incident_id": incident_id,
                                 "capability_id": cid, "qty": 2, "expected_version": 1},
                                {"X-Actor-Id": "cmd"})
        self.assertEqual(201, status)
        aid = reserve["resource_id"]
        status, body = route(self.service, "POST", "/allocations/confirm",
                             {"request_id": "cf", "allocation_id": aid, "qty": 1,
                              "expected_version": 1}, {"X-Actor-Id": "cmd"})
        self.assertEqual(200, status)

        # 企业不能越权指挥
        status, denied = route(self.service, "POST", "/allocations/reserve",
                               {"request_id": "res-denied", "incident_id": incident_id,
                                "capability_id": cid, "qty": 1, "expected_version": 2},
                               {"X-Actor-Id": "e1"})
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", denied["error"])

        # 关闭后迟到信号进入附录
        route(self.service, "POST", "/incidents/close",
              {"request_id": "close", "incident_id": incident_id}, {"X-Actor-Id": "cmd"})
        status, late = route(self.service, "POST", "/signals",
                             {"request_id": "late", "site_id": "site-1", "signal_type": "voc",
                              "fingerprint": "fp-late", "severity": "high"},
                             {"X-Actor-Id": "e1"})
        self.assertEqual(201, status)
        self.assertEqual("signal", late["resource_type"])
        status, closed = route(self.service, "GET", f"/incidents/{incident_id}", None,
                               {"X-Actor-Id": "au"})
        self.assertEqual("closed", closed["status"])
        self.assertGreaterEqual(closed["aggregate"]["late_arrival_count"], 1)

        # 审计可查、哈希链完整
        status, audit = route(self.service, "GET", "/audit-events", None, {"X-Actor-Id": "au"})
        self.assertEqual(200, status)
        actions = {item["action"] for item in audit["items"]}
        self.assertIn("incident.opened", actions)
        self.assertIn("capability.reserved", actions)
        self.assertIn("signal.appendixed", actions)
        status, health = route(self.service, "GET", "/health", None)
        self.assertTrue(health["audit_valid"])

    def test_capability_catalog_route(self):
        status, body = route(self.service, "POST", "/capabilities",
                             {"request_id": "cap", "kind": "technician", "total_qty": 2,
                              "shared_qty": 1}, {"X-Actor-Id": "e1"})
        self.assertEqual(201, status)
        status, catalog = route(self.service, "GET", "/capabilities", None, {"X-Actor-Id": "e1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(catalog["my_capabilities"]))
        status, listing = route(self.service, "GET", "/incidents", None, {"X-Actor-Id": "cmd"})
        self.assertEqual(200, status)
        self.assertIsInstance(listing["items"], list)


if __name__ == "__main__":
    unittest.main()
