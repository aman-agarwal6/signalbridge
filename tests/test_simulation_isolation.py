"""Simulation scenarios must not share resources, or unrelated cases form cross-case patterns.

The frozen v1 challenge catalog shares resources deliberately and measures only R1/R2;
see simulations/challenge_suite.py and tests/test_challenge_execution.py.
"""

from collections import defaultdict
from datetime import datetime, timezone

from django.test import SimpleTestCase

from simulations import scenarios

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


class SimulationIsolationTests(SimpleTestCase):
    def test_simulation_scenarios_never_share_a_resource(self):
        owners = defaultdict(set)
        for case in scenarios.build_scenarios(NOW):
            for delivery in case["deliveries"]:
                owners[delivery["event"]["resource"]].add(case["id"])
        shared = {resource: cases for resource, cases in owners.items() if len(cases) > 1}
        self.assertEqual(shared, {})

    def test_within_a_case_distinct_readings_keep_distinct_resources(self):
        # R1 needs three distinct resources from one actor; scoping must not merge them.
        case = next(
            c for c in scenarios.build_scenarios(NOW) if c["id"] == "distinct_private_failures"
        )
        self.assertEqual(len({d["event"]["resource"] for d in case["deliveries"]}), 3)
