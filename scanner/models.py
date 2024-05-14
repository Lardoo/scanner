from django.db import models

class ScanResult(models.Model):
    url = models.URLField(max_length=200)
    vulnerability_type = models.CharField(max_length=100)
    details = models.TextField()
    mitigation = models.TextField()
    payload = models.TextField(null=True, blank=True)  # Add the payload field with null and blank options

    def __str__(self):
        return self.url