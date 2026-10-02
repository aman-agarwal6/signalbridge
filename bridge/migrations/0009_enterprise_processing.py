import re

from django.db import migrations, models


def backfill_subjects(apps, schema_editor):
    Event = apps.get_model("bridge", "Event")
    records = Event.objects.using(schema_editor.connection.alias).filter(
        operation="membership.change"
    )
    for event in records.only("pk", "payload").iterator(chunk_size=500):
        payload = event.payload
        membership = payload.get("membership") if isinstance(payload, dict) else None
        subject = membership.get("subject") if isinstance(membership, dict) else None
        if (
            isinstance(payload, dict)
            and payload.get("schema_version") == 2
            and isinstance(subject, str)
            and re.fullmatch("[a-f0-9]{64}", subject)
        ):
            records.filter(pk=event.pk).update(membership_subject=subject)


class Migration(migrations.Migration):
    dependencies = [("bridge", "0008_membership_assertions")]
    operations = [
        migrations.AddField(
            model_name="event",
            name="membership_subject",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.RunPython(backfill_subjects, migrations.RunPython.noop),
        migrations.AddField(
            model_name="event",
            name="processing_attempts",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="event",
            name="processing_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="event",
            name="processed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="event",
            name="processed_by",
            field=models.CharField(blank=True, default="", max_length=40),
        ),
        migrations.AddIndex(
            model_name="event",
            index=models.Index(
                fields=["integration", "state", "available_at", "received_at"],
                name="sb_event_app_queue",
            ),
        ),
        migrations.AddIndex(
            model_name="event",
            index=models.Index(
                fields=["integration", "resource", "membership_subject", "occurred_at"],
                name="sb_event_subject_time",
            ),
        ),
    ]
