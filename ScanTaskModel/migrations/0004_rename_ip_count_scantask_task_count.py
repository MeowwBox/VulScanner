# Generated by Django 3.2.1 on 2021-06-10 15:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ScanTaskModel', '0003_scantask_ip_range'),
    ]

    operations = [
        migrations.RenameField(
            model_name='scantask',
            old_name='ip_count',
            new_name='task_count',
        ),
    ]
