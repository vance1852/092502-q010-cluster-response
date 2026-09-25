"""集群联防：共享能力声明、带版本预占/确认、撤回与账本平衡测试。"""

import unittest
from datetime import datetime, timezone

from cluster_response_core.clock import FixedClock
from cluster_response_core.errors import ConflictError, PermissionDenied, ValidationError
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database

from tests.test_incidents import build_service, RULE, LEADS, MINUTES


class CapabilityFlowTest(unittest.TestCase):
    def setUp(self):
        self.database, self.service = build_service()
        self.service.publish_plan(request_id="plan", actor_id="adm", plan_id="plan-a",
                                  cluster_id="cluster-a", escalation_rule=RULE,
                                  lead_by_classification=LEADS, response_minutes_by_level=MINUTES)
        self.incident_id = self.service.report_signal(
            request_id="sig-1", actor_id="e1", site_id="s1", signal_type="voc",
            fingerprint="fp-1", severity="high", supply_code="manifold-7").resource_id

    def tearDown(self):
        self.database.close()

    def _cap_row(self, capability_id: str):
        return self.database.connection.execute(
            "SELECT * FROM capabilities WHERE capability_id=?", (capability_id,)
        ).fetchone()

    def _alloc_row(self, allocation_id: str):
        return self.database.connection.execute(
            "SELECT * FROM allocations WHERE allocation_id=?", (allocation_id,)
        ).fetchone()

    def _assert_balanced(self, capability_id: str):
        cap = self._cap_row(capability_id)
        self.assertLessEqual(cap["reserved_qty"] + cap["confirmed_qty"], cap["shared_qty"])
        allocated = self.database.connection.execute(
            "SELECT COALESCE(SUM(qty-confirmed_qty-released_qty-revoked_qty),0) AS open_qty,"
            "COALESCE(SUM(confirmed_qty),0) AS confirmed FROM allocations "
            "WHERE capability_id=? AND status IN ('reserved','partially_confirmed')",
            (capability_id,),
        ).fetchone()
        self.assertEqual(cap["reserved_qty"], allocated["open_qty"])
        confirmed_sum = self.database.connection.execute(
            "SELECT COALESCE(SUM(confirmed_qty),0) AS c FROM allocations WHERE capability_id=?",
            (capability_id,),
        ).fetchone()["c"]
        self.assertEqual(cap["confirmed_qty"], confirmed_sum)

    def test_declare_validation(self):
        with self.assertRaises(ValidationError):
            self.service.declare_capability(
                request_id="bad1", actor_id="e1", kind="equipment", total_qty=2, shared_qty=3)
        with self.assertRaises(ValidationError):
            self.service.declare_capability(
                request_id="bad2", actor_id="e1", kind="drone", total_qty=2, shared_qty=2)

    def test_versioned_reserve_confirm_and_idempotent_replay(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=5, shared_qty=3)
        cid = cap.resource_id
        reserve = self.service.reserve_capability(
            request_id="res", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=2, expected_version=1)
        aid = reserve.resource_id
        self.assertEqual(2, self._cap_row(cid)["version"])
        # 旧版本的再次预占被拒绝（乐观并发）
        with self.assertRaises(ConflictError):
            self.service.reserve_capability(
                request_id="res-stale", actor_id="cmd", incident_id=self.incident_id,
                capability_id=cid, qty=1, expected_version=1)
        # 超量预占被拒绝
        with self.assertRaises(ConflictError):
            self.service.reserve_capability(
                request_id="res-over", actor_id="cmd", incident_id=self.incident_id,
                capability_id=cid, qty=2, expected_version=2)
        # 带预占版本确认
        self.service.confirm_capability(
            request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
        with self.assertRaises(ConflictError):
            self.service.confirm_capability(
                request_id="cf2", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
        replay = self.service.confirm_capability(
            request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
        self.assertTrue(replay.replayed)
        # 幂等重放没有再次扣减
        cap_row = self._cap_row(cid)
        self.assertEqual(1, cap_row["reserved_qty"])
        self.assertEqual(1, cap_row["confirmed_qty"])
        self._assert_balanced(cid)

    def test_partial_confirm_then_release(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="technician", total_qty=4, shared_qty=4)
        cid = cap.resource_id
        reserve = self.service.reserve_capability(
            request_id="res", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=3, expected_version=1)
        aid = reserve.resource_id
        self.service.confirm_capability(
            request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
        release = self.service.release_capability(
            request_id="rel", actor_id="cmd", allocation_id=aid, qty=2, expected_version=2)
        # 3 个预占中 1 个确认、2 个释放：预占量清零，状态为部分确认（已全部处置）
        self.assertEqual("partially_confirmed", self._alloc_row(aid)["status"])
        cap_row = self._cap_row(cid)
        self.assertEqual(0, cap_row["reserved_qty"])
        self.assertEqual(1, cap_row["confirmed_qty"])
        self.assertEqual(4, cap_row["shared_qty"])
        self._assert_balanced(cid)

    def test_withdraw_only_affects_unconfirmed_share(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=10, shared_qty=4)
        cid = cap.resource_id
        a1 = self.service.reserve_capability(
            request_id="r1", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=2, expected_version=1).resource_id
        a2 = self.service.reserve_capability(
            request_id="r2", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=2, expected_version=2).resource_id
        self.service.confirm_capability(
            request_id="c1", actor_id="cmd", allocation_id=a1, qty=1, expected_version=1)
        # 当前 shared=4, reserved=3, confirmed=1, free=0。撤回 2 -> 撤销 2 个未确认预占
        self.service.withdraw_capability(
            request_id="wd", actor_id="e1", capability_id=cid, qty=2, expected_version=4)
        revoked = self._revoked(cid)
        self.assertEqual(2, sum(item["qty"] for item in revoked))
        # 已确认的 1 个绝不能被撤回：尝试撤回超过 (shared - confirmed) 的量
        with self.assertRaises(ConflictError):
            self.service.withdraw_capability(
                request_id="wd2", actor_id="e1", capability_id=cid, qty=2, expected_version=5)
        cap_row = self._cap_row(cid)
        self.assertEqual(1, cap_row["confirmed_qty"])
        self.assertEqual(2, cap_row["shared_qty"])
        self._assert_balanced(cid)

    def _revoked(self, cid):
        rows = self.database.connection.execute(
            "SELECT allocation_id, revoked_qty FROM allocations WHERE capability_id=? AND revoked_qty>0",
            (cid,),
        ).fetchall()
        return [{"allocation_id": r["allocation_id"], "qty": r["revoked_qty"]} for r in rows]

    def test_other_enterprise_cannot_withdraw_or_command(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=3, shared_qty=3)
        cid = cap.resource_id
        with self.assertRaises(PermissionDenied):
            self.service.withdraw_capability(
                request_id="wd-x", actor_id="e2", capability_id=cid, qty=1, expected_version=1)
        with self.assertRaises(PermissionDenied):
            self.service.reserve_capability(
                request_id="res-x", actor_id="e2", incident_id=self.incident_id,
                capability_id=cid, qty=1, expected_version=1)

    def test_reserve_rejected_after_incident_closed_leaves_balance(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=3, shared_qty=3)
        cid = cap.resource_id
        self.service.close_incident(request_id="close", actor_id="cmd",
                                    incident_id=self.incident_id)
        with self.assertRaises(ConflictError):
            self.service.reserve_capability(
                request_id="late", actor_id="cmd", incident_id=self.incident_id,
                capability_id=cid, qty=1, expected_version=1)
        self._assert_balanced(cid)

    def test_close_auto_releases_unconfirmed_reservations(self):
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=4, shared_qty=4)
        cid = cap.resource_id
        aid = self.service.reserve_capability(
            request_id="res", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=3, expected_version=1).resource_id
        self.service.confirm_capability(
            request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
        self.service.close_incident(request_id="close", actor_id="cmd",
                                    incident_id=self.incident_id)
        cap_row = self._cap_row(cid)
        # 未确认的 2 个被自动释放：reserved=0，confirmed=1 保留
        self.assertEqual(0, cap_row["reserved_qty"])
        self.assertEqual(1, cap_row["confirmed_qty"])
        alloc = self._alloc_row(aid)
        self.assertEqual(2, alloc["released_qty"])
        self.assertEqual("partially_confirmed", alloc["status"])
        self._assert_balanced(cid)

    def test_mid_operation_failure_rolls_back_resource_deduction(self):
        import cluster_response_core.service as service_module
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=5, shared_qty=3)
        cid = cap.resource_id
        original_append = service_module.append_event

        def failing_append(*args, **kwargs):
            if kwargs.get("action") == "capability.reserved":
                raise RuntimeError("模拟审计写入失败")
            return original_append(*args, **kwargs)

        service_module.append_event = failing_append
        try:
            with self.assertRaises(RuntimeError):
                self.service.reserve_capability(
                    request_id="res-fail", actor_id="cmd", incident_id=self.incident_id,
                    capability_id=cid, qty=2, expected_version=1)
        finally:
            service_module.append_event = original_append
        # 预占与扣减必须同时回滚：没有 allocation，能力账本不变，版本不变
        self.assertEqual(0, self.database.connection.execute(
            "SELECT COUNT(*) FROM allocations WHERE request_id='res-fail'").fetchone()[0])
        cap_row = self._cap_row(cid)
        self.assertEqual(0, cap_row["reserved_qty"])
        self.assertEqual(1, cap_row["version"])
        # 同一 request_id 在故障后仍可正常重试
        retry = self.service.reserve_capability(
            request_id="res-fail", actor_id="cmd", incident_id=self.incident_id,
            capability_id=cid, qty=2, expected_version=1)
        self.assertFalse(retry.replayed)
        self._assert_balanced(cid)

    def test_concurrent_reserves_never_oversell(self):
        import threading
        cap = self.service.declare_capability(
            request_id="cap", actor_id="e1", kind="equipment", total_qty=10, shared_qty=3)
        cid = cap.resource_id
        results: list[str] = []
        lock = threading.Lock()

        def attempt(index: int):
            # 真实客户端：版本冲突后重读当前版本再重试，直到成功或容量不足
            outcome = "conflict"
            for _ in range(10):
                version = self._cap_row(cid)["version"]
                try:
                    self.service.reserve_capability(
                        request_id=f"parallel-{index}", actor_id="cmd",
                        incident_id=self.incident_id, capability_id=cid, qty=1,
                        expected_version=version)
                    outcome = "ok"
                    break
                except ConflictError as exc:
                    if "不足" in str(exc):
                        outcome = "insufficient"
                        break
                    continue
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(3, results.count("ok"))
        self.assertEqual(3, results.count("insufficient"))
        self.assertEqual(0, results.count("conflict"))
        self._assert_balanced(cid)

    def test_state_survives_restart_with_single_chain_of_command(self):
        import tempfile
        from pathlib import Path
        from cluster_response_core.storage import Database as Db

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite3"
            database = Db(path)
            service = DomainService(database, FixedClock(datetime(2026, 9, 25, 8, tzinfo=timezone.utc)))
            service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="street", name="街道", is_regulator=True)
            service.register_actor(request_id="adm", actor_id="bootstrap", new_actor_id="adm",
                                   display_name="管理员", role="admin", organization_id="street")
            service.register_actor(request_id="cmd", actor_id="adm", new_actor_id="cmd",
                                   display_name="指挥", role="operator", organization_id="street")
            service.register_organization(request_id="o1", actor_id="adm",
                                          organization_id="o1", name="厂")
            service.register_actor(request_id="e1", actor_id="adm", new_actor_id="e1",
                                   display_name="厂负责人", role="operator", organization_id="o1")
            service.register_site(request_id="s1", actor_id="e1", site_id="s1",
                                  organization_id="o1", name="车间", timezone_name="Asia/Shanghai",
                                  cluster_id="c1")
            service.publish_plan(request_id="plan", actor_id="adm", plan_id="plan-x",
                                 cluster_id="c1",
                                 escalation_rule=RULE, lead_by_classification=LEADS,
                                 response_minutes_by_level=MINUTES)
            iid = service.report_signal(
                request_id="sig", actor_id="e1", site_id="s1", signal_type="voc",
                fingerprint="fp", severity="high").resource_id
            cid = service.declare_capability(
                request_id="cap", actor_id="e1", kind="equipment", total_qty=2,
                shared_qty=2).resource_id
            aid = service.reserve_capability(
                request_id="res", actor_id="cmd", incident_id=iid, capability_id=cid,
                qty=1, expected_version=1).resource_id
            service.confirm_capability(
                request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
            database.close()

            restarted_db = Db(path)
            restarted = DomainService(restarted_db,
                                      FixedClock(datetime(2026, 9, 25, 9, tzinfo=timezone.utc)))
            view = restarted.incident_view(iid, "cmd")
            self.assertEqual("cmd", view["lead_actor_id"])
            self.assertEqual("open", view["status"])
            # 重启后幂等请求仍然只返回原回执，不会重复扣减
            replay = restarted.confirm_capability(
                request_id="cf", actor_id="cmd", allocation_id=aid, qty=1, expected_version=1)
            self.assertTrue(replay.replayed)
            cap = restarted_db.connection.execute(
                "SELECT * FROM capabilities WHERE capability_id=?", (cid,)).fetchone()
            self.assertEqual(1, cap["confirmed_qty"])
            valid, count = restarted.verify_audit()
            self.assertTrue(valid)
            self.assertGreater(count, 0)
            restarted_db.close()


if __name__ == "__main__":
    unittest.main()
