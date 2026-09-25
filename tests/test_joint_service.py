"""集群联防协同服务的核心规则测试。"""

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cluster_response_core.clock import ManualClock
from cluster_response_core.errors import (
    ConflictError, PermissionDenied, ValidationError,
)
from cluster_response_core.joint_service import JointDefenseService
from cluster_response_core.service import DomainService
from cluster_response_core.storage import Database


def _plan_body():
    return {
        "levels": [
            {"level": "L1", "rank": 1, "deadline_minutes": 60,
             "commander_role": "operator", "display_name": "厂级"},
            {"level": "L2", "rank": 2, "deadline_minutes": 30,
             "commander_role": "operator", "display_name": "园区级"},
            {"level": "L3", "rank": 3, "deadline_minutes": 15,
             "commander_role": "admin", "display_name": "区域级"},
        ],
        "rules": [
            {"rule_id": "multi-plant", "distinct_sources_min": 2,
             "max_severity_min": "medium", "set_level": "L2"},
            {"rule_id": "regional", "distinct_sources_min": 3,
             "max_severity_min": "high", "set_level": "L3"},
        ],
        "default_level": "L1",
        "group_keys": ["park-a", "park-b", "park-c"],
        "append_window_minutes": 30,
    }


class JointDefenseTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = ManualClock(datetime(2026, 9, 25, 8, tzinfo=timezone.utc))
        self.base = DomainService(self.database, self.clock)
        self.service = JointDefenseService(self.database, self.clock)
        self.base.register_organization(request_id="org-gov", actor_id="bootstrap",
                                        organization_id="gov", name="街道")
        self.base.register_actor(request_id="actor-admin", actor_id="bootstrap",
                                 new_actor_id="admin", display_name="管理员",
                                 role="admin", organization_id="gov")
        for suffix, org in (("1", "f1"), ("2", "f2"), ("3", "f3")):
            self.base.register_organization(request_id=f"org-{suffix}", actor_id="admin",
                                            organization_id=org, name=f"家具厂{suffix}")
        self.base.register_actor(request_id="actor-cmd", actor_id="admin",
                                 new_actor_id="cmd", display_name="现场指挥",
                                 role="operator", organization_id="gov")
        self.base.register_actor(request_id="actor-aud", actor_id="admin",
                                 new_actor_id="aud", display_name="监管员",
                                 role="auditor", organization_id="gov")
        for suffix, org in (("1", "f1"), ("2", "f2"), ("3", "f3")):
            self.base.register_actor(request_id=f"actor-op{suffix}", actor_id="admin",
                                     new_actor_id=f"op{suffix}", display_name=f"厂{suffix}操作员",
                                     role="operator", organization_id=org)
            self.base.register_site(request_id=f"site-{suffix}", actor_id=f"op{suffix}",
                                    site_id=f"site{suffix}", organization_id=org,
                                    name=f"喷涂车间{suffix}", timezone_name="Asia/Shanghai")
        self.service.publish_plan(request_id="plan-1", actor_id="admin", plan_id="voc",
                                  name="废气联防预案", **_plan_body())

    def tearDown(self):
        self.database.close()

    def _open_multi_plant_incident(self):
        first = self.service.report_signal(
            request_id="sig-1", actor_id="op1", group_key="park-a", signal_type="voc",
            severity="medium", dedup_key="d-1", site_id="site1")
        second = self.service.report_signal(
            request_id="sig-2", actor_id="op2", group_key="park-a", signal_type="voc",
            severity="high", dedup_key="d-1", site_id="site2")
        return first.data["incident_id"], second

    # ---- 信号归并与预案升级 ------------------------------------------------

    def test_repeated_signal_merges_sources_and_escalates(self):
        incident_id, second = self._open_multi_plant_incident()
        self.assertTrue(second.data["merged"])
        self.assertEqual("L2", second.data["level"])
        self.assertEqual("multi-plant", second.data["escalated"]["rule_id"])
        view = self.service.get_incident("aud", incident_id)
        self.assertEqual(1, view["aggregate"]["live_signal_count"])
        self.assertEqual(2, view["aggregate"]["live_source_count"])
        self.assertEqual(2, view["aggregate"]["distinct_organizations"])
        self.assertEqual({"medium": 1, "high": 1}, view["aggregate"]["severity_breakdown"])

    def test_same_request_replays_without_second_source(self):
        self.service.report_signal(
            request_id="dup", actor_id="op1", group_key="park-a", signal_type="voc",
            severity="medium", dedup_key="d-1", site_id="site1")
        replay = self.service.report_signal(
            request_id="dup", actor_id="op1", group_key="park-a", signal_type="voc",
            severity="medium", dedup_key="d-1", site_id="site1")
        self.assertTrue(replay.receipt.replayed)

    def test_request_id_rejects_changed_payload(self):
        kwargs = dict(actor_id="op1", group_key="park-a", signal_type="voc",
                      dedup_key="d-1", site_id="site1")
        self.service.report_signal(request_id="change", severity="low", **kwargs)
        with self.assertRaises(ConflictError):
            self.service.report_signal(request_id="change", severity="high", **kwargs)

    def test_three_plants_high_escalates_to_regional_level(self):
        self.service.report_signal(request_id="s1", actor_id="op1", group_key="park-c",
                                   signal_type="voc", severity="high", dedup_key="z",
                                   site_id="site1")
        self.service.report_signal(request_id="s2", actor_id="op2", group_key="park-c",
                                   signal_type="voc", severity="high", dedup_key="z",
                                   site_id="site2")
        result = self.service.report_signal(request_id="s3", actor_id="op3",
                                            group_key="park-c", signal_type="voc",
                                            severity="high", dedup_key="z", site_id="site3")
        self.assertEqual("L3", result.data["level"])

    def test_enterprise_cannot_report_for_other_site(self):
        with self.assertRaises(PermissionDenied):
            self.service.report_signal(request_id="x", actor_id="op2", group_key="park-a",
                                       signal_type="voc", severity="low", dedup_key="d",
                                       site_id="site1")

    # ---- 版本化预案 --------------------------------------------------------

    def test_incident_binds_plan_version_at_open(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        body = _plan_body()
        body["levels"][0]["deadline_minutes"] = 90
        body["levels"][0]["display_name"] = "新厂级"
        self.service.publish_plan(request_id="plan-2", actor_id="admin", plan_id="voc",
                                  name="废气联防预案v2", **body)
        self.assertEqual(2, self.service.get_plan("voc").version)
        self.assertEqual(60, self.service.get_plan("voc", 1).levels[0].deadline_minutes)
        # 进行中的事件即使在新预案发布后仍绑定旧版本，后续信号继续并入。
        joined = self.service.report_signal(request_id="sig-join", actor_id="op1",
                                            group_key="park-a", signal_type="voc",
                                            severity="low", dedup_key="d-join",
                                            site_id="site1")
        self.assertEqual(incident_id, joined.data["incident_id"])
        self.assertEqual(1, self.service.get_incident("aud", incident_id)["plan_version"])
        # 关闭并越过附录窗口后开立的新事件使用新版本预案。
        self.service.close_incident(request_id="close", actor_id="cmd",
                                    incident_id=incident_id)
        self.clock.advance(minutes=31)
        fresh = self.service.report_signal(request_id="sig-new", actor_id="op1",
                                           group_key="park-a", signal_type="voc",
                                           severity="low", dedup_key="d-new", site_id="site1")
        self.assertNotEqual(incident_id, fresh.data["incident_id"])
        self.assertEqual(2, self.service.get_incident("aud", fresh.data["incident_id"])["plan_version"])

    def test_plan_rejects_duplicate_level_and_bad_reference(self):
        with self.assertRaises(ValidationError):
            self.service.publish_plan(
                request_id="bad-1", actor_id="admin", plan_id="bad", name="x",
                levels=[{"level": "A", "rank": 1, "deadline_minutes": 10,
                         "commander_role": "operator"},
                        {"level": "B", "rank": 1, "deadline_minutes": 5,
                         "commander_role": "operator"}],
                default_level="A")
        with self.assertRaises(ValidationError):
            self.service.publish_plan(
                request_id="bad-2", actor_id="admin", plan_id="bad2", name="x",
                levels=[{"level": "A", "rank": 1, "deadline_minutes": 10,
                         "commander_role": "operator"}],
                rules=[{"rule_id": "r", "distinct_sources_min": 2,
                        "max_severity_min": "high", "set_level": "Z"}],
                default_level="A")

    # ---- 指挥链 ------------------------------------------------------------

    def test_commander_assignment_requires_plan_level_role(self):
        self.service.report_signal(request_id="r-1", actor_id="op1", group_key="park-c",
                                   signal_type="voc", severity="high", dedup_key="z",
                                   site_id="site1")
        self.service.report_signal(request_id="r-2", actor_id="op2", group_key="park-c",
                                   signal_type="voc", severity="high", dedup_key="z",
                                   site_id="site2")
        third = self.service.report_signal(request_id="r-3", actor_id="op3",
                                           group_key="park-c", signal_type="voc",
                                           severity="high", dedup_key="z", site_id="site3")
        with self.assertRaises(PermissionDenied):
            self.service.assign_commander(request_id="cmd-bad", actor_id="admin",
                                          incident_id=third.data["incident_id"],
                                          commander_actor_id="cmd")
        result = self.service.assign_commander(
            request_id="cmd-ok", actor_id="admin",
            incident_id=third.data["incident_id"], commander_actor_id="admin")
        self.assertEqual(1, result.data["commander_version"])

    def test_concurrent_commander_assignment_stale_version_rejected(self):
        opened = self.service.report_signal(request_id="o-1", actor_id="op1",
                                            group_key="park-b", signal_type="dust",
                                            severity="low", dedup_key="b", site_id="site1")
        self.service.assign_commander(request_id="c-1", actor_id="admin",
                                      incident_id=opened.data["incident_id"],
                                      commander_actor_id="cmd", expected_version=0)
        with self.assertRaises(ConflictError):
            self.service.assign_commander(request_id="c-2", actor_id="admin",
                                          incident_id=opened.data["incident_id"],
                                          commander_actor_id="admin", expected_version=0)
        chain = self.service.commander_chain("aud", opened.data["incident_id"])
        self.assertEqual(1, chain["commander_version"])
        self.assertEqual(1, len(chain["history"]))

    def test_only_current_commander_can_close(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        with self.assertRaises(PermissionDenied):
            self.service.close_incident(request_id="close-x", actor_id="op1",
                                        incident_id=incident_id)
        closed = self.service.close_incident(request_id="close", actor_id="cmd",
                                             incident_id=incident_id, note="风险解除")
        self.assertIn("closed_at", closed.data)

    # ---- 备用能力预占与确认 ------------------------------------------------

    def _prepare_capacities(self, incident_id):
        self.service.declare_capacity(
            request_id="cap-a", actor_id="op1", capacity_id="cap-ads",
            resource_type="活性炭吸附装置", total_qty=4, shared_qty=2, site_id="site1")
        self.service.declare_capacity(
            request_id="cap-b", actor_id="op2", capacity_id="cap-tech",
            resource_type="治污技术员", total_qty=3, shared_qty=2)
        return self.service.reserve_capacities(
            request_id="reserve", actor_id="cmd", incident_id=incident_id,
            requests=[{"capacity_id": "cap-ads", "qty": 2, "expected_version": 1},
                      {"capacity_id": "cap-tech", "qty": 1, "expected_version": 1}])

    def test_batch_reserve_is_atomic_on_partial_failure(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        reserved = self._prepare_capacities(incident_id)
        self.assertEqual(2, len(reserved.data["allocations"]))
        self.service.declare_capacity(
            request_id="cap-c", actor_id="op2", capacity_id="cap-fan",
            resource_type="备用风机", total_qty=1, shared_qty=1)
        with self.assertRaises(ConflictError):
            self.service.reserve_capacities(
                request_id="reserve-2", actor_id="cmd", incident_id=incident_id,
                requests=[{"capacity_id": "cap-fan", "qty": 1},
                          {"capacity_id": "cap-ads", "qty": 1}])
        capacities = {c["capacity_id"]: c
                      for c in self.service.list_capacities("admin")["items"]}
        self.assertEqual(0, capacities["cap-fan"]["reserved_qty"])
        self.assertEqual(1, capacities["cap-fan"]["available_qty"])
        self.assertEqual(2, capacities["cap-ads"]["reserved_qty"])

    def test_stale_capacity_version_rejected(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        self.service.declare_capacity(
            request_id="cap-a", actor_id="op1", capacity_id="cap-ads",
            resource_type="吸附装置", total_qty=4, shared_qty=2)
        self.service.reserve_capacities(
            request_id="reserve", actor_id="cmd", incident_id=incident_id,
            requests=[{"capacity_id": "cap-ads", "qty": 1, "expected_version": 1}])
        with self.assertRaises(ConflictError):
            self.service.reserve_capacities(
                request_id="reserve-stale", actor_id="cmd", incident_id=incident_id,
                requests=[{"capacity_id": "cap-ads", "qty": 1, "expected_version": 1}])

    def test_confirm_then_batch_conflict_rolls_back_all(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        reserved = self._prepare_capacities(incident_id)
        ids = [item["allocation_id"] for item in reserved.data["allocations"]]
        confirm = self.service.confirm_allocations(
            request_id="confirm", actor_id="cmd", incident_id=incident_id,
            allocation_ids=[ids[0]])
        self.assertEqual("confirmed", confirm.data["allocations"][0]["status"])
        with self.assertRaises(ConflictError):
            self.service.confirm_allocations(
                request_id="confirm-again", actor_id="cmd", incident_id=incident_id,
                allocation_ids=[ids[0], ids[1]])
        untouched = self.service.get_incident("aud", incident_id)["allocations"]
        statuses = {item["allocation_id"]: item["status"] for item in untouched}
        self.assertEqual("confirmed", statuses[ids[0]])
        self.assertEqual("reserved", statuses[ids[1]])

    def test_withdrawal_only_evicts_unconfirmed_quantity(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        reserved = self._prepare_capacities(incident_id)
        ids = {item["capacity_id"]: item["allocation_id"]
               for item in reserved.data["allocations"]}
        self.service.confirm_allocations(
            request_id="confirm", actor_id="cmd", incident_id=incident_id,
            allocation_ids=[ids["cap-ads"]])
        # 已确认量不可被企业撤回挤掉。
        with self.assertRaises(ConflictError):
            self.service.update_capacity(
                request_id="shrink", actor_id="op1", capacity_id="cap-ads",
                total_qty=4, shared_qty=1, expected_version=3)
        # 撤回技术员共享量只释放未确认预占。
        updated = self.service.update_capacity(
            request_id="withdraw-tech", actor_id="op2", capacity_id="cap-tech",
            total_qty=3, shared_qty=0, expected_version=2)
        self.assertEqual(1, len(updated.data["evicted"]))
        self.assertEqual(ids["cap-tech"], updated.data["evicted"][0]["allocation_id"])
        allocations = self.service.get_incident("aud", incident_id)["allocations"]
        statuses = {item["capacity_id"]: item["status"] for item in allocations}
        self.assertEqual("confirmed", statuses["cap-ads"])
        self.assertEqual("released", statuses["cap-tech"])
        capacities = {c["capacity_id"]: c
                      for c in self.service.list_capacities("admin")["items"]}
        self.assertEqual(0, capacities["cap-tech"]["available_qty"])
        self.assertEqual(0, capacities["cap-ads"]["available_qty"])
        self.assertEqual(2, capacities["cap-ads"]["confirmed_qty"])

    def test_non_commander_cannot_reserve(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        self.service.declare_capacity(
            request_id="cap-a", actor_id="op1", capacity_id="cap-ads",
            resource_type="吸附装置", total_qty=2, shared_qty=2)
        with self.assertRaises(PermissionDenied):
            self.service.reserve_capacities(
                request_id="reserve-x", actor_id="op1", incident_id=incident_id,
                requests=[{"capacity_id": "cap-ads", "qty": 1}])

    # ---- 跨企业裁剪 --------------------------------------------------------

    def test_enterprise_view_hides_other_sources_and_allocations(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        reserved = self._prepare_capacities(incident_id)
        ids = [item["allocation_id"] for item in reserved.data["allocations"]]
        self.service.confirm_allocations(request_id="confirm", actor_id="cmd",
                                         incident_id=incident_id, allocation_ids=ids[:1])
        view = self.service.get_incident("op2", incident_id)
        self.assertNotIn("sources", view["signals"][0])
        self.assertNotIn("allocations", view)
        self.assertEqual(1, view["signals"][0]["own_sources"][0]["report_count"])
        self.assertEqual(1, view["signals"][0]["other_sources"]["count"])
        self.assertEqual(1, view["signals"][0]["other_sources"]["distinct_organizations"])
        self.assertEqual({"medium": 1}, view["signals"][0]["other_sources"]["severity_breakdown"])
        self.assertEqual(1, view["responsibility"]["own_reserved_shared_qty"])
        self.assertEqual(0, view["responsibility"]["own_confirmed_shared_qty"])

    def test_regulator_and_commander_see_full_provenance(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        for viewer in ("aud", "cmd"):
            view = self.service.get_incident(viewer, incident_id)
            self.assertEqual(2, len(view["signals"][0]["sources"]))
            self.assertIn("allocations", view)
        organizations = {source["organization_id"] for source
                         in self.service.get_incident("aud", incident_id)["signals"][0]["sources"]}
        self.assertEqual({"f1", "f2"}, organizations)

    def test_non_participant_enterprise_cannot_read_incident(self):
        incident_id, _ = self._open_multi_plant_incident()
        with self.assertRaises(PermissionDenied):
            self.service.get_incident("op3", incident_id)

    def test_capacity_catalog_is_anonymous_for_other_enterprises(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        self._prepare_capacities(incident_id)
        items = {c["capacity_id"]: c
                 for c in self.service.list_capacities("op2")["items"]}
        self.assertIsNone(items["cap-ads"]["owner_organization_id"])
        self.assertTrue(items["cap-ads"]["anonymous"])
        self.assertNotIn("total_qty", items["cap-ads"])
        self.assertEqual("f2", items["cap-tech"]["owner_organization_id"])
        admin_items = {c["capacity_id"]: c
                       for c in self.service.list_capacities("aud")["items"]}
        self.assertEqual("f1", admin_items["cap-ads"]["owner_organization_id"])

    def test_incident_list_scoped_to_participation(self):
        incident_id, _ = self._open_multi_plant_incident()
        other = self.service.report_signal(
            request_id="other", actor_id="op3", group_key="park-b", signal_type="dust",
            severity="low", dedup_key="b", site_id="site3")
        op2_ids = {i["incident_id"]
                   for i in self.service.list_incidents("op2")["items"]}
        op3_ids = {i["incident_id"]
                   for i in self.service.list_incidents("op3")["items"]}
        self.assertIn(incident_id, op2_ids)
        self.assertNotIn(incident_id, op3_ids)
        self.assertIn(other.data["incident_id"], op3_ids)
        admin_ids = {i["incident_id"]
                     for i in self.service.list_incidents("admin")["items"]}
        self.assertEqual({incident_id, other.data["incident_id"]}, admin_ids)

    # ---- 关闭与附录 --------------------------------------------------------

    def test_late_signals_enter_appendix_then_window_expires(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        self.service.close_incident(request_id="close", actor_id="cmd",
                                    incident_id=incident_id)
        late = self.service.report_signal(
            request_id="late-1", actor_id="op1", group_key="park-a", signal_type="voc",
            severity="high", dedup_key="late", site_id="site1")
        self.assertEqual("appendix", late.data["phase"])
        self.assertEqual(incident_id, late.data["incident_id"])
        # 与生效信号相同 dedup_key 的迟到告警必须能在附录中独立存在。
        same_key = self.service.report_signal(
            request_id="late-same-key", actor_id="op1", group_key="park-a",
            signal_type="voc", severity="high", dedup_key="d-1", site_id="site1")
        self.assertEqual("appendix", same_key.data["phase"])
        self.assertFalse(same_key.data["merged"])
        merged = self.service.report_signal(
            request_id="late-2", actor_id="op2", group_key="park-a", signal_type="voc",
            severity="medium", dedup_key="late", site_id="site2")
        self.assertTrue(merged.data["merged"])
        view = self.service.get_incident("aud", incident_id)
        self.assertEqual("closed", view["status"])
        self.assertEqual(1, view["aggregate"]["live_signal_count"])
        self.assertEqual(2, view["aggregate"]["appendix_signal_count"])
        late_entry = next(item for item in view["appendix"]
                          if item["dedup_key"] == "late")
        self.assertEqual(2, len(late_entry["sources"]))
        same_key_entry = next(item for item in view["appendix"]
                              if item["dedup_key"] == "d-1")
        self.assertEqual(1, len(same_key_entry["sources"]))
        # 终态不可被重新指挥或预占。
        with self.assertRaises(ConflictError):
            self.service.assign_commander(request_id="reassign", actor_id="admin",
                                          incident_id=incident_id, commander_actor_id="admin")
        self.service.declare_capacity(
            request_id="cap-x", actor_id="op1", capacity_id="cap-x",
            resource_type="风机", total_qty=1, shared_qty=1)
        with self.assertRaises(ConflictError):
            self.service.reserve_capacities(
                request_id="reserve-x", actor_id="cmd", incident_id=incident_id,
                requests=[{"capacity_id": "cap-x", "qty": 1}])
        # 越过附录窗口后，迟到信号开立新事件，旧终态保持不变。
        self.clock.advance(minutes=31)
        fresh = self.service.report_signal(
            request_id="fresh", actor_id="op1", group_key="park-a", signal_type="voc",
            severity="low", dedup_key="late", site_id="site1")
        self.assertTrue(fresh.data["new_incident"])
        self.assertNotEqual(incident_id, fresh.data["incident_id"])
        self.assertEqual("live", fresh.data["phase"])
        view = self.service.get_incident("aud", incident_id)
        self.assertEqual("closed", view["status"])
        self.assertEqual(2, view["aggregate"]["appendix_signal_count"])

    def test_withdraw_signal_source_only_removes_own_origin(self):
        incident_id, _ = self._open_multi_plant_incident()
        result = self.service.withdraw_signal_source(
            request_id="withdraw", actor_id="op1", incident_id=incident_id,
            dedup_key="d-1", site_id="site1")
        self.assertFalse(result.data["signal_removed"])
        view = self.service.get_incident("aud", incident_id)
        self.assertEqual(1, view["aggregate"]["live_source_count"])
        self.assertEqual("f2", view["signals"][0]["sources"][0]["organization_id"])
        with self.assertRaises(PermissionDenied):
            self.service.withdraw_signal_source(
                request_id="withdraw-x", actor_id="op2", incident_id=incident_id,
                dedup_key="d-1", site_id="site1")

    # ---- 重启与审计 --------------------------------------------------------

    def test_state_and_audit_chain_survive_restart(self):
        incident_id, _ = self._open_multi_plant_incident()
        self.service.assign_commander(request_id="assign", actor_id="admin",
                                      incident_id=incident_id, commander_actor_id="cmd")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "joint.sqlite3"
            with sqlite3.connect(path) as target:
                self.database.connection.backup(target)
            restarted_db = Database(path)
            restarted = JointDefenseService(restarted_db, self.clock)
            replay = restarted.report_signal(
                request_id="sig-2", actor_id="op2", group_key="park-a", signal_type="voc",
                severity="high", dedup_key="d-1", site_id="site2")
            self.assertTrue(replay.receipt.replayed)
            chain = restarted.commander_chain("aud", incident_id)
            self.assertEqual("cmd", chain["current_commander_actor_id"])
            self.assertEqual(1, chain["commander_version"])
            self.assertEqual(1, restarted.get_plan("voc").version)
            valid, count = self.base.verify_audit()
            self.assertTrue(valid)
            self.assertGreater(count, 0)
            restarted_db.close()


    # ---- 并发 --------------------------------------------------------------

    def _shared_file_stack(self):
        """创建多个连接指向同一文件数据库的服务，用于真实并发验证。"""

        directory = tempfile.mkdtemp()
        path = Path(directory) / "concurrent.sqlite3"
        seed = Database(path)
        seed_clock = ManualClock(datetime(2026, 9, 25, 8, tzinfo=timezone.utc))
        base = DomainService(seed, seed_clock)
        joint = JointDefenseService(seed, seed_clock)
        base.register_organization(request_id="org-gov", actor_id="bootstrap",
                                   organization_id="gov", name="街道")
        base.register_actor(request_id="actor-admin", actor_id="bootstrap",
                            new_actor_id="admin", display_name="管理员", role="admin",
                            organization_id="gov")
        for suffix, org in (("1", "f1"), ("2", "f2")):
            base.register_organization(request_id=f"org-{suffix}", actor_id="admin",
                                       organization_id=org, name=f"家具厂{suffix}")
            base.register_actor(request_id=f"actor-op{suffix}", actor_id="admin",
                                new_actor_id=f"op{suffix}", display_name=f"厂{suffix}",
                                role="operator", organization_id=org)
            base.register_site(request_id=f"site-{suffix}", actor_id=f"op{suffix}",
                               site_id=f"site{suffix}", organization_id=org,
                               name=f"车间{suffix}", timezone_name="Asia/Shanghai")
        base.register_actor(request_id="actor-cmd1", actor_id="admin", new_actor_id="cmd1",
                            display_name="指挥一", role="operator", organization_id="gov")
        base.register_actor(request_id="actor-cmd2", actor_id="admin", new_actor_id="cmd2",
                            display_name="指挥二", role="operator", organization_id="gov")
        base.register_actor(request_id="actor-auditor", actor_id="admin", new_actor_id="aud",
                            display_name="监管员", role="auditor", organization_id="gov")
        joint.publish_plan(request_id="plan-1", actor_id="admin", plan_id="voc",
                           name="预案", **_plan_body())
        seed.close()
        return path

    def _peer(self, path):
        database = Database(path)
        clock = ManualClock(datetime(2026, 9, 25, 8, tzinfo=timezone.utc))
        return database, JointDefenseService(database, clock)

    def test_concurrent_confirmation_has_single_winner(self):
        path = self._shared_file_stack()
        opener_db, opener = self._peer(path)
        first = opener.report_signal(request_id="s1", actor_id="op1", group_key="park-a",
                                     signal_type="voc", severity="medium", dedup_key="d",
                                     site_id="site1")
        opener.report_signal(request_id="s2", actor_id="op2", group_key="park-a",
                             signal_type="voc", severity="high", dedup_key="d", site_id="site2")
        incident_id = first.data["incident_id"]
        opener.assign_commander(request_id="as1", actor_id="admin", incident_id=incident_id,
                                commander_actor_id="cmd1")
        opener.declare_capacity(request_id="cap1", actor_id="op1", capacity_id="cap1",
                                resource_type="装置", total_qty=2, shared_qty=2)
        reserved = opener.reserve_capacities(
            request_id="rs1", actor_id="cmd1", incident_id=incident_id,
            requests=[{"capacity_id": "cap1", "qty": 1}])
        allocation_id = reserved.data["allocations"][0]["allocation_id"]
        opener_db.close()

        outcomes = []
        barrier = threading.Barrier(2)

        def worker(command_actor, request_id):
            database, service = self._peer(path)
            try:
                barrier.wait()
                # 第二个连接需要先把 cmd2 设为牵头人才能确认；通过同一条指挥链裁决。
                service.confirm_allocations(
                    request_id=request_id, actor_id=command_actor,
                    incident_id=incident_id, allocation_ids=[allocation_id])
                outcomes.append("confirmed")
            except ConflictError:
                outcomes.append("conflict")
            except Exception as exc:  # pragma: no cover - 仅用于暴露意外异常
                outcomes.append(f"error:{type(exc).__name__}")
            finally:
                database.close()

        threads = [threading.Thread(target=worker, args=("cmd1", f"confirm-{i}"))
                   for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, outcomes.count("confirmed"), outcomes)
        self.assertEqual(1, outcomes.count("conflict"), outcomes)

        checker_db, checker = self._peer(path)
        view = checker.get_incident("aud", incident_id)
        allocation = next(item for item in view["allocations"]
                          if item["allocation_id"] == allocation_id)
        self.assertEqual("confirmed", allocation["status"])
        self.assertEqual(1, view["aggregate"]["confirmed_qty"])
        self.assertEqual(0, view["aggregate"]["reserved_qty"])
        capacities = {c["capacity_id"]: c
                      for c in checker.list_capacities("aud")["items"]}
        self.assertEqual(1, capacities["cap1"]["confirmed_qty"])
        self.assertEqual(0, capacities["cap1"]["reserved_qty"])
        self.assertEqual(1, capacities["cap1"]["available_qty"])
        checker_db.close()

    def test_concurrent_reserve_never_oversells(self):
        path = self._shared_file_stack()
        opener_db, opener = self._peer(path)
        opened = opener.report_signal(request_id="s1", actor_id="op1", group_key="park-a",
                                      signal_type="voc", severity="low", dedup_key="d",
                                      site_id="site1")
        incident_id = opened.data["incident_id"]
        opener.assign_commander(request_id="as1", actor_id="admin", incident_id=incident_id,
                                commander_actor_id="cmd1")
        opener.declare_capacity(request_id="cap1", actor_id="op1", capacity_id="cap1",
                                resource_type="装置", total_qty=1, shared_qty=1)
        opener_db.close()

        outcomes = []
        barrier = threading.Barrier(2)

        def worker(index):
            database, service = self._peer(path)
            try:
                barrier.wait()
                service.reserve_capacities(
                    request_id=f"rs-{index}", actor_id="cmd1", incident_id=incident_id,
                    requests=[{"capacity_id": "cap1", "qty": 1}])
                outcomes.append("reserved")
            except ConflictError:
                outcomes.append("conflict")
            finally:
                database.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, outcomes.count("reserved"), outcomes)
        self.assertEqual(1, outcomes.count("conflict"), outcomes)

        checker_db, checker = self._peer(path)
        capacities = {c["capacity_id"]: c
                      for c in checker.list_capacities("aud")["items"]}
        self.assertEqual(1, capacities["cap1"]["reserved_qty"])
        self.assertEqual(0, capacities["cap1"]["available_qty"])
        self.assertLessEqual(capacities["cap1"]["reserved_qty"],
                             capacities["cap1"]["shared_qty"])
        checker_db.close()

    def test_concurrent_commander_assignment_keeps_unique_chain(self):
        path = self._shared_file_stack()
        opener_db, opener = self._peer(path)
        opened = opener.report_signal(request_id="s1", actor_id="op1", group_key="park-a",
                                      signal_type="voc", severity="low", dedup_key="d",
                                      site_id="site1")
        incident_id = opened.data["incident_id"]
        opener_db.close()

        outcomes = []
        barrier = threading.Barrier(2)

        def worker(commander, request_id):
            database, service = self._peer(path)
            try:
                barrier.wait()
                service.assign_commander(request_id=request_id, actor_id="admin",
                                         incident_id=incident_id,
                                         commander_actor_id=commander,
                                         expected_version=0)
                outcomes.append(commander)
            except ConflictError:
                outcomes.append("conflict")
            finally:
                database.close()

        threads = [
            threading.Thread(target=worker, args=("cmd1", "assign-1")),
            threading.Thread(target=worker, args=("cmd2", "assign-2")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        winners = [value for value in outcomes if value != "conflict"]
        self.assertEqual(1, len(winners), outcomes)
        checker_db, checker = self._peer(path)
        chain = checker.commander_chain("aud", incident_id)
        self.assertEqual(1, chain["commander_version"])
        self.assertEqual(1, len(chain["history"]))
        self.assertEqual(winners[0], chain["current_commander_actor_id"])
        self.assertEqual(winners[0],
                         checker.get_incident("aud", incident_id)["commander_actor_id"])
        checker_db.close()


if __name__ == "__main__":
    unittest.main()
