from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("bridge", "0007_soc_delivery")]
    operations = [
        migrations.AddField(
            model_name="ingestkey",
            name="can_assert_membership",
            field=models.BooleanField(default=False),
        ),
        migrations.AddIndex(
            model_name="event",
            index=models.Index(
                fields=["integration", "resource", "occurred_at"], name="sb_event_resource_time"
            ),
        ),
    ]
