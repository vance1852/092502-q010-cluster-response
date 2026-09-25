import unittest

from cluster_response_core.acceptance import run


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["first_replayed"])
        self.assertTrue(result["second_replayed"])
        self.assertEqual(1, result["records"])
        joint = result["joint_defense"]
        self.assertTrue(joint["incident_opened"])
        self.assertTrue(joint["merged_and_escalated"])
        self.assertEqual(1, joint["commander_version"])
        self.assertEqual(2, joint["reserved_count"])
        self.assertEqual(2, joint["confirmed_count"])
        self.assertTrue(joint["enterprise_field_isolation"])
        self.assertTrue(joint["regulator_full_provenance"])
        self.assertEqual("appendix", joint["late_signal_phase"])
        self.assertTrue(joint["terminal_untouched"])
        self.assertEqual(1, joint["appendix_count"])


if __name__ == "__main__":
    unittest.main()
