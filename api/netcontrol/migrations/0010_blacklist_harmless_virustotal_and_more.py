# Generated by Django 5.1.2 on 2024-11-25 19:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netcontrol', '0009_whitelist_harmless_virustotal_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklist',
            name='harmless_virustotal',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='blacklist',
            name='malicious_virustotal',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='blacklist',
            name='suspicious_virustotal',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='blacklist',
            name='undetected_virustotal',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='blacklist',
            name='virustotal_reputation',
            field=models.IntegerField(null=True),
        ),
    ]
