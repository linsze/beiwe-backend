# Generated by Django 3.2.16 on 2023-03-02 14:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('database', '0100_participant_last_get_latest_device_settings'),
    ]

    operations = [
        migrations.CreateModel(
            name='ParticipantDeletionEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('files_deleted_count', models.BigIntegerField(default=0)),
                ('purge_confirmed_time', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('participant', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='deletion_event', to='database.participant')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
