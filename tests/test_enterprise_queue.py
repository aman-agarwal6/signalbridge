"""Analyst queues preserve app boundaries and distinguish work from remediation."""

from datetime import timedelta

from django.utils import timezone

from bridge.models import Investigation
from tests.test_enterprise_cases import CaseFixture


class EnterpriseQueueTests(CaseFixture):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.analyst)
        self.path = "/investigations/?app=" + self.app.slug

    def test_mine_is_scoped_to_current_user_and_app(self):
        self.case.assignee = self.membership
        self.case.save()
        foreign = Investigation.objects.create(
            integration=self.other,
            assignee=self.membership,
            rule="R1",
            correlation="f" * 64,
            title="Foreign private case",
            severity="high",
            explanation="Foreign",
        )
        response = self.client.get(self.path + "&queue=mine")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([c.pk for c in response.context["cases"]], [self.case.pk])
        self.assertNotContains(response, foreign.title)
        self.assertContains(response, "Assigned analyst")

    def test_overdue_excludes_resolved_and_unscheduled_cases(self):
        self.case.due_at = timezone.now() - timedelta(hours=1)
        self.case.save()
        response = self.client.get(self.path + "&queue=overdue")
        self.assertEqual(response.context["result_count"], 1)
        self.assertContains(response, "Overdue")
        self.case.status = "resolved"
        self.case.save()
        self.assertEqual(self.client.get(self.path + "&queue=overdue").context["result_count"], 0)

    def test_unacknowledged_and_unassigned_are_open_work(self):
        for queue in ("unacknowledged", "unassigned"):
            self.assertEqual(
                self.client.get(self.path + "&queue=" + queue).context["result_count"], 1
            )
        self.case.assignee = self.membership
        self.case.acknowledged_at = timezone.now()
        self.case.save()
        for queue in ("unacknowledged", "unassigned"):
            self.assertEqual(
                self.client.get(self.path + "&queue=" + queue).context["result_count"], 0
            )

    def test_rule_catalog_filter_and_business_context_are_visible_and_escaped(self):
        self.case.rule = "R5"
        self.case.save()
        self.app.business_owner = "<script>not-an-owner</script>"
        self.app.save()
        response = self.client.get(self.path + "&rule=R5")
        self.assertEqual(response.context["result_count"], 1)
        self.assertContains(response, "R5")
        self.assertContains(response, 'value="R5" selected')
        self.assertContains(response, 'value="R4"')
        self.assertContains(response, "Asset criticality:")
        self.assertContains(response, "&lt;script&gt;not-an-owner&lt;/script&gt;")
        self.assertNotContains(response, "<script>not-an-owner</script>")
        self.assertContains(
            self.client.get("/detections/?app=" + self.app.slug), "Version bounded-denials-v1"
        )

    def test_viewer_can_read_queue_but_cannot_use_it_to_gain_write_access(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(self.path + "&queue=unassigned").status_code, 200)
        response = self.client.post(
            f"/cases/{self.case.pk}/operations/", {"version": 1, "operation": "acknowledge"}
        )
        self.assertIn(response.status_code, (403, 404))
        self.case.refresh_from_db()
        self.assertIsNone(self.case.acknowledged_at)
