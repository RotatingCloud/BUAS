from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    background_color = models.CharField(max_length=7, default='#6D6D6D')
    text_color = models.CharField(max_length=7, default='#FFFFFF')

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()
