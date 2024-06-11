from django.http import HttpResponseRedirect
from django.urls import reverse
from functools import wraps

def premium_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            # Redirect to login if not authenticated
            return HttpResponseRedirect(reverse('dashboard'))
        if not hasattr(request.user, 'profile') or not request.user.profile.premium_status:
            # Redirect to a "payment required" page if not premium
            return HttpResponseRedirect(reverse('payment_required'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view
