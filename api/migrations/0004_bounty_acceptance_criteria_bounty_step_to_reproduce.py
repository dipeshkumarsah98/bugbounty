# Generated by Django 5.1.3 on 2024-12-08 05:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_user_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='bounty',
            name='acceptance_criteria',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bounty',
            name='step_to_reproduce',
            field=models.TextField(blank=True, null=True),
        ),
    ]
