from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Profile(models.Model):
    """ Profile model """
    username = models.CharField(max_length=120, unique=True)
    last_name = models.CharField(max_length=120, blank=True ,null=True)
    first_name = models.CharField(max_length=120, blank=True ,null=True)
    email = models.EmailField(max_length=120, blank=True ,null=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['username']

    def __str__(self):
        return self.username
