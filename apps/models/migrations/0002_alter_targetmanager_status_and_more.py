# Generated by Django 4.2.5 on 2024-02-09 10:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('models', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='targetmanager',
            name='status',
            field=models.IntegerField(choices=[(0, '初始化'), (1, '运行中'), (2, '完成'), (3, '删除'), (4, '失败'), (5, '未知错误')], default=0, verbose_name='任务状态'),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='file_name',
            field=models.CharField(db_index=True, max_length=255, verbose_name='pocsuite3漏洞文件名字'),
        ),
    ]