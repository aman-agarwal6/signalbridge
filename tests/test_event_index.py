from django.db import connection
from django.test import SimpleTestCase, TestCase

from bridge.models import Event
from scripts.benchmark_event_index import benchmark


class EventIndexSchemaTests(TestCase):
    def test_migrated_database_has_scoped_received_time_index(self):
        with connection.cursor() as cursor:
            indexes = connection.introspection.get_constraints(cursor, Event._meta.db_table)
        index = indexes["sb_event_app_received"]
        self.assertTrue(index["index"])
        self.assertEqual(index["columns"], ["integration_id", "received_at"])


class EventIndexMicrobenchmarkTests(SimpleTestCase):
    def test_same_scope_and_cutoff_with_less_database_work(self):
        result = benchmark(history=1000, repeats=1)
        self.assertEqual(result["before"]["matched_records"], 60)
        self.assertEqual(result["after"]["matched_records"], 60)
        self.assertLess(
            result["after"]["sqlite_vm_instructions"],
            result["before"]["sqlite_vm_instructions"] // 3,
        )
        self.assertIn("sb_event_app_received", " ".join(result["after"]["query_plan"]))

    def test_workload_limits_reject_unbounded_or_ambiguous_inputs(self):
        for history in (True, 999, 20001, "1000"):
            with self.assertRaises(ValueError):
                benchmark(history=history)
        for repeats in (True, 0, 51, "1"):
            with self.assertRaises(ValueError):
                benchmark(repeats=repeats)
