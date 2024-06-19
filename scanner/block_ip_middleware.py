# block_ip_middleware.py
from django.http import HttpResponseForbidden
from django.utils import timezone
from datetime import timedelta
from .models import FailedLoginAttempt

class BlockIPMiddleware:
    """
    Middleware to block IP addresses with too many failed login attempts.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = request.META.get('REMOTE_ADDR')
        
        # Check failed attempts in the last 5 minutes
        five_minutes_ago = timezone.now() - timedelta(minutes=5)
        failed_attempts = FailedLoginAttempt.objects.filter(ip_address=client_ip, attempt_time__gte=five_minutes_ago)
        
        if failed_attempts.count() >= 5:
            return HttpResponseForbidden("Too many failed login attempts. Try again after 5 minutes.")

        response = self.get_response(request)
        return response
