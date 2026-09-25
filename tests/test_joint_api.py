"""集群联防协同 HTTP 路由测试。"""

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib import request as urlrequest

from cluster_response_core.api import Handler, route
from cluster_response_core.joint_service import JointDefenseService
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database


class JointApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)
        self.joint = JointDefenseService(self.database)
        self.service.register_organization(request_id="org-gov", actor_id="bootstrap",
                                           organization_id="gov", name="街道")
        self.service.register_actor(request_id="actor-admin", actor_id="bootstrap",
                                    new_actor_id="admin", display_name="管理员",
                                    role="admin", organization_id="gov")
        for suffix, org in (("1", "f1"), ("2", "f2")):
            self.service.register_organization(request_id=f"org-{suffix}", actor_id="admin",
                                               organization_id=org, name=f"家具厂{suffix}")
            self.service.register_actor(request_id=f"actor-op{suffix}", actor_id="admin",
                                        new_actor_id=f"op{suffix}", display_name=f"厂{suffix}",
                                        role="operator", organization_id=org)
            self.service.register_site(request_id=f"site-{suffix}", actor_id=f"op{suffix}",
                                       site_id=f"site{suffix}", organization_id=org,
                                       name=f"车间{suffix}", timezone_name="Asia/Shanghai")
        self.service.register_actor(request_id="actor-cmd", actor_id="admin",
                                    new_actor_id="cmd", display_name="指挥",
                                    role="operator", organization_id="gov")
        self.service.register_actor(request_id="actor-aud", actor_id="admin",
                                    new_actor_id="aud", display_name="监管",
                                    role="auditor", organization_id="gov")
        self.plan = {
            "request_id": "plan-1",
            "plan_id": "voc", "name": "预案",
            "levels": [
                {"level": "L1", "rank": 1, "deadline_minutes": 60,
                 "commander_role": "operator", "display_name": "厂级"},
                {"level": "L2", "rank": 2, "deadline_minutes": 30,
                 "commander_role": "operator", "display_name": "园区级"},
            ],
            "rules": [{"rule_id": "multi", "distinct_sources_min": 2,
                       "max_severity_min": "medium", "set_level": "L2"}],
            "default_level": "L1", "group_keys": ["park-a"],
            "append_window_minutes": 30,
        }

    def tearDown(self):
        self.database.close()

    def _call(self, method, path, body=None, actor="admin", expected=None):
        status, payload = route(self.service, method, path, body,
                                {"X-Actor-Id": actor})
        if expected is not None:
            self.assertEqual(expected, status, payload)
        return status, payload

    def _open_incident(self):
        self._call("POST", "/plans", self.plan)
        self._call("POST", "/signals", {
            "request_id": "sig-1", "group_key": "park-a", "signal_type": "voc",
            "severity": "medium", "dedup_key": "d-1", "site_id": "site1"}, actor="op1")
        _, second = self._call("POST", "/signals", {
            "request_id": "sig-2", "group_key": "park-a", "signal_type": "voc",
            "severity": "high", "dedup_key": "d-1", "site_id": "site2"}, actor="op2")
        return second["result"]["incident_id"]

    def test_full_collaboration_flow_over_http(self):
        incident_id = self._open_incident()
        status, _ = self._call("POST", f"/incidents/{incident_id}/commander",
                               {"request_id": "assign", "commander_actor_id": "cmd",
                                "reason": "首发处置"})
        self.assertEqual(200, status)
        self._call("POST", "/capacities", {
            "request_id": "cap-a", "capacity_id": "cap-ads",
            "resource_type": "吸附装置", "total_qty": 4, "shared_qty": 2,
            "site_id": "site1"}, actor="op1", expected=201)
        status, reserved = self._call("POST", f"/incidents/{incident_id}/reservations",
                                      {"request_id": "reserve",
                                       "requests": [{"capacity_id": "cap-ads", "qty": 2,
                                                     "expected_version": 1}]}, actor="cmd")
        self.assertEqual(201, status)
        allocation_id = reserved["result"]["allocations"][0]["allocation_id"]
        self._call("POST", f"/incidents/{incident_id}/confirmations",
                   {"request_id": "confirm", "allocation_ids": [allocation_id]},
                   actor="cmd")
        # 企业视图被裁剪。
        status, enterprise_view = self._call("GET", f"/incidents/{incident_id}", actor="op2")
        self.assertNotIn("sources", enterprise_view["signals"][0])
        self.assertNotIn("allocations", enterprise_view)
        # 监管视图保留完整来源。
        status, regulator_view = self._call("GET", f"/incidents/{incident_id}", actor="aud")
        self.assertEqual(2, len(regulator_view["signals"][0]["sources"]))
        # 指挥链可追溯。
        status, chain = self._call("GET", f"/incidents/{incident_id}/command-chain")
        self.assertEqual("cmd", chain["current_commander_actor_id"])
        self.assertEqual(1, len(chain["history"]))

    def test_close_then_late_signal_is_appendix(self):
        incident_id = self._open_incident()
        self._call("POST", f"/incidents/{incident_id}/commander",
                   {"request_id": "assign", "commander_actor_id": "cmd"})
        self._call("POST", f"/incidents/{incident_id}/close",
                   {"request_id": "close", "note": "解除"}, actor="cmd")
        status, late = self._call("POST", "/signals", {
            "request_id": "late", "group_key": "park-a", "signal_type": "voc",
            "severity": "high", "dedup_key": "late", "site_id": "site1"}, actor="op1")
        self.assertEqual(201, status)
        self.assertEqual("appendix", late["result"]["phase"])
        _, view = self._call("GET", f"/incidents/{incident_id}", actor="aud")
        self.assertEqual("closed", view["status"])
        self.assertEqual(1, view["aggregate"]["appendix_signal_count"])

    def test_non_participant_gets_403(self):
        incident_id = self._open_incident()
        self.service.register_organization(request_id="org-3", actor_id="admin",
                                           organization_id="f3", name="家具厂三")
        self.service.register_actor(request_id="actor-op3", actor_id="admin",
                                    new_actor_id="op3", display_name="厂三",
                                    role="operator", organization_id="f3")
        status, payload = self._call("GET", f"/incidents/{incident_id}", actor="op3")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_capacity_shortage_returns_conflict_and_nothing_changes(self):
        incident_id = self._open_incident()
        self._call("POST", f"/incidents/{incident_id}/commander",
                   {"request_id": "assign", "commander_actor_id": "cmd"})
        self._call("POST", "/capacities", {
            "request_id": "cap-a", "capacity_id": "cap-ads",
            "resource_type": "吸附装置", "total_qty": 1, "shared_qty": 1,
            "site_id": "site1"}, actor="op1")
        status, payload = self._call("POST", f"/incidents/{incident_id}/reservations",
                                     {"request_id": "oversell",
                                      "requests": [{"capacity_id": "cap-ads", "qty": 2}]},
                                     actor="cmd")
        self.assertEqual(409, status)
        self.assertEqual("conflict", payload["error"])
        _, listing = self._call("GET", "/capacities", actor="admin")
        self.assertEqual(0, listing["items"][0]["reserved_qty"])

    def test_capacity_routes_require_known_capacity(self):
        status, payload = self._call("POST", "/capacities/missing/update",
                                     {"request_id": "up", "total_qty": 1,
                                      "shared_qty": 1, "expected_version": 1})
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"])

    def test_threaded_server_concurrent_writes_do_not_corrupt(self):
        self.database.close()
        database = Database(":memory:")
        service = DomainService(database)
        Handler.service = service
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def post(path, body, actor):
                data = json.dumps(body).encode("utf-8")
                req = urlrequest.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                         method="POST")
                req.add_header("Content-Type", "application/json")
                req.add_header("X-Actor-Id", actor)
                with urlrequest.urlopen(req) as response:
                    return response.status, json.loads(response.read())

            post("/organizations", {"request_id": "og", "organization_id": "gov",
                                    "name": "街道"}, "bootstrap")
            post("/actors", {"request_id": "aa", "new_actor_id": "admin",
                             "display_name": "管", "role": "admin",
                             "organization_id": "gov"}, "bootstrap")
            post("/plans", {"request_id": "p1", "plan_id": "voc", "name": "预案",
                            "levels": [{"level": "L1", "rank": 1,
                                        "deadline_minutes": 60,
                                        "commander_role": "operator",
                                        "display_name": "厂级"}],
                            "default_level": "L1", "group_keys": ["g"]}, "admin")
            post("/organizations", {"request_id": "o1", "organization_id": "f1",
                                    "name": "厂一"}, "admin")
            post("/actors", {"request_id": "a1", "new_actor_id": "op1",
                             "display_name": "员", "role": "operator",
                             "organization_id": "f1"}, "admin")
            post("/sites", {"request_id": "s1", "site_id": "site1",
                            "organization_id": "f1", "name": "车间",
                            "timezone_name": "Asia/Shanghai"}, "op1")

            results = []

            def worker(index):
                try:
                    status, _ = post("/signals", {
                        "request_id": f"sig-{index}", "group_key": "g",
                        "signal_type": "voc", "severity": "low",
                        "dedup_key": f"d-{index}", "site_id": "site1"}, "op1")
                    results.append(status)
                except Exception as exc:  # pragma: no cover
                    results.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertTrue(all(code == 201 for code in results), results)
            status, health = route(service, "GET", "/health", None)
            self.assertTrue(health["audit_valid"])
        finally:
            server.shutdown()
            server.server_close()
            database.close()


if __name__ == "__main__":
    unittest.main()
