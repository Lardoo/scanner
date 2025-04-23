# admin.py
from django.contrib import admin
from .models import Profile

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'premium_status', 'cash_pending')
    list_editable = ('premium_status', 'cash_pending')
    search_fields = ('user__username',)
