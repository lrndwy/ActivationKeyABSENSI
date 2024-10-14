from django.db import models

# Create your models here.

class activation_key(models.Model):
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=255)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return self.key