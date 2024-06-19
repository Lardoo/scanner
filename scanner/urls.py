from django.urls import path
from . import views
from .views import PaypalPaymentView, payment_success ,RegisterView

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('scan/', views.scan, name='scan'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    #path('paypal/validate/', PaypalValidatePaymentView.as_view(), name='paypalvalidate'),
    path('paypal/create/', PaypalPaymentView.as_view(), name='paypal_create'),
    path('paypal_cancel/', views.paypal_cancel, name='paypal_cancel'),
    #path('paypal_execute/', PaypalExecutePaymentView.as_view(), name='paypal_execute'),
    path('paypal_execute/', views.paypal_execute, name='payment_execute'),
    path('payment_success/', views.payment_success, name='payment_success'),
    path('otp_verification/', views.otp_verification, name='otp_verification'),
    path('payment_required/', views.payment_required_view, name='payment_required'),
    path('scan_results/', views.scan_results, name='scan_results'),
    path('download_scan_pdf/', views.download_scan_pdf, name='download_scan_pdf')
]