# Generated by Django 4.1.7 on 2023-04-03 17:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('basicAuth', '0002_userprofile_text_color'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userprofile',
            old_name='background_color',
            new_name='primary_color',
        ),
        migrations.RenameField(
            model_name='userprofile',
            old_name='text_color',
            new_name='secondary_color',
        ),
    ]
