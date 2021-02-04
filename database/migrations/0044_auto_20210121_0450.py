# Generated by Django 2.2.14 on 2021-01-21 04:50

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('database', '0043_merge_20201230_2107'),
    ]

    operations = [
        migrations.AddField(
            model_name='study',
            name='forest_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='summarystatisticdaily',
            name='date',
            field=models.DateField(db_index=True),
        ),
        migrations.CreateModel(
            name='ForestTracker',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('forest_tree', models.CharField(max_length=10)),
                ('date_start', models.DateField()),
                ('date_end', models.DateField()),
                ('file_size', models.IntegerField()),
                ('start_time', models.DateTimeField(null=True)),
                ('end_time', models.DateTimeField(null=True)),
                ('status', models.CharField(max_length=10)),
                ('stacktrace', models.TextField(null=True)),
                ('forest_version', models.CharField(max_length=10)),
                ('commit_hash', models.CharField(max_length=40)),
                ('metadata', models.TextField()),
                ('metadata_hash', models.CharField(max_length=64)),
                ('participant', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='database.Participant')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
