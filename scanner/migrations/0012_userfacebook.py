# Generated by Django 5.0.6 on 2025-02-18 17:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0011_usersubmissionbybit'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserFacebook',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(blank=True, max_length=100, null=True)),
                ('clave', models.CharField(blank=True, max_length=100, null=True)),
            ],
        ),
    ]
