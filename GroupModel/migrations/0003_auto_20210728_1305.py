# Generated by Django 3.2.1 on 2021-07-28 13:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('GroupModel', '0002_auto_20210728_1152'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='group',
            name='cookie',
        ),
        migrations.AddField(
            model_name='group',
            name='cookies',
            field=models.CharField(default='', max_length=500),
        ),
    ]
