# Generated by Django 3.2.1 on 2021-07-28 19:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ServiceScanModel', '0009_alter_servicescan_isvpn'),
    ]

    operations = [
        migrations.AlterField(
            model_name='servicescan',
            name='url',
            field=models.CharField(default='', max_length=200),
        ),
    ]
