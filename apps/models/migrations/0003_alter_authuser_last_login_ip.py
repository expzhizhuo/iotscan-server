# Generated by Django 4.2.5 on 2024-02-22 08:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('models', '0002_alter_targetmanager_status_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authuser',
            name='last_login_ip',
            field=models.GenericIPAddressField(default='', verbose_name='登陆ip'),
        ),
    ]
