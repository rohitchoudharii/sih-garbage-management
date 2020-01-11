# Generated by Django 3.0.1 on 2020-01-11 06:35

import core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_garbagedata'),
    ]

    operations = [
        migrations.AlterField(
            model_name='garbagedata',
            name='photo',
            field=models.FileField(upload_to='images/garbage/', validators=[core.validators.validate_photo_extension]),
        ),
    ]
