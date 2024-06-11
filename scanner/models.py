from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    url = models.URLField()
    vulnerability_type = models.CharField(max_length=255)
    details = models.TextField()
    mitigation = models.TextField()
    payload = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    premium_status = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username



@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()