import requests
from django.shortcuts import render,redirect
from django.http import HttpResponse
from .models import ScanResult
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode,urljoin
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages



from django.views.decorators.csrf import csrf_exempt


#start of paypal imports
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from .utils import make_paypal_payment,verify_paypal_payment#, execute_paypal_payment
from django.views import View
from django.middleware.csrf import get_token
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login as auth_login
from django.contrib.auth import authenticate, login as auth_login ,  logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required 
from django.core.mail import send_mail
import random
import string
from .forms import RegistrationForm
from django.utils.decorators import method_decorator
from .models import Profile
from .decorators import premium_required
from django.utils.decorators import method_decorator
from django.template.loader import render_to_string
#from weasyprint import HTML
from datetime import datetime,timedelta
from xhtml2pdf import pisa
import io
from io import BytesIO
from .models import FailedLoginAttempt
from django.core.cache import cache  # For storing attempt count
import time  # Add this to simulate long running tasks (remove in production)
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.urls import reverse














def index(request):
    return render(request,'index.html')


def paymentpax(request):
    return render(request,'home3.html')






@login_required
def profile(request):
    return render(request, 'profile.html', {'user': request.user})




@login_required
@premium_required
def scan(request):
    if request.method == 'POST':
        target_url = request.POST.get('target_url')
        deep_scan = request.POST.get('deep_scan') == 'on'
        
        # Generate a unique scan ID
        scan_id = f"scan_{request.user.id}_{int(time.time())}"
        
        # Initialize progress in cache
        cache.set(scan_id, {'status': 'Initializing', 'progress': 0})
        
        # Start the scan (this should be done asynchronously in a real-world scenario)
        if deep_scan:
            endpoints = crawl_website(target_url)
        else:
            endpoints = [target_url]
        
        vulnerabilities = []
        total_endpoints = len(endpoints)
        
        for index, endpoint in enumerate(endpoints):
            vulnerabilities.extend(detect_sql_injection(endpoint))
            # Update progress in cache
            progress = int(((index + 1) / total_endpoints) * 100)
            cache.set(scan_id, {'status': 'Scanning', 'progress': progress})
        
        # Save scan results to the database
        scan_results = []
        for vulnerability in vulnerabilities:
            result = ScanResult.objects.create(
                url=vulnerability['endpoint'],
                vulnerability_type=vulnerability['type'],
                details=vulnerability['details'],
                mitigation=vulnerability['mitigation'],
                payload=vulnerability.get('payload', None),
                user=request.user,
                scan_id=scan_id  # Save scan_id
            )
            scan_results.append(result)
        
        # Finalize progress
        cache.set(scan_id, {'status': 'Complete', 'progress': 100, 'results': [result.id for result in scan_results]})
        
        return JsonResponse({'scan_id': scan_id})
    
    return render(request, 'scan.html')


@login_required
def scan_progress(request, scan_id):
    progress = cache.get(scan_id, {'status': 'Unknown', 'progress': 0})
    return JsonResponse(progress)



@login_required
def download_scan_pdf(request):
    scan_id = request.GET.get('scan_id')

    if not scan_id:
        return HttpResponse("Scan ID is required.", status=400)

    scan_results = ScanResult.objects.filter(user=request.user, scan_id=scan_id)

    if not scan_results.exists():
        return HttpResponse("No scan results found.", status=404)

    # Use the earliest created result as the scan's starting time
    first_result = scan_results.order_by('created_at').first()
    last_result = scan_results.order_by('-created_at').first()

    # Assuming ScanResult model has a DateTimeField named 'created_at'
    scan_start_time = first_result.created_at
    scan_end_time = last_result.created_at
    scan_duration = scan_end_time - scan_start_time
    scanned_url = first_result.url

    context = {
        'scan_results': scan_results,
        'scanned_url': scanned_url,
        'scan_id': scan_id,
        'scan_start_time': scan_start_time,
        'scan_end_time': scan_end_time,
        'scan_duration': scan_duration,
    }

    template_path = 'scan_results_pdf.html'
    html = render_to_string(template_path, context)

    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)

    if not pdf.err:
        response = HttpResponse(result.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="scan_results_{scan_id}.pdf"'
        return response

    return HttpResponse("Error rendering PDF", status=500)




@login_required
def scan_results(request, scan_id):
    scan_results = ScanResult.objects.filter(user=request.user, scan_id=scan_id)

    if not scan_results.exists():
        context = {
            'no_results': True,
            'scan_id': scan_id
        }
        return render(request, 'scan_results.html', context)

    # Use the earliest created result as the scan's starting time
    first_result = scan_results.order_by('created_at').first()
    last_result = scan_results.order_by('-created_at').first()

    scan_start_time = first_result.created_at
    scan_end_time = last_result.created_at
    scan_duration = scan_end_time - scan_start_time
    scanned_url = first_result.url

    context = {
        'scan_results': scan_results,
        'scanned_url': scanned_url,
        'scan_id': scan_id,
        'scan_start_time': scan_start_time,
        'scan_end_time': scan_end_time,
        'scan_duration': scan_duration,
        'no_results': False
    }

    return render(request, 'scan_results.html', context)



# Function to detect SQL injection vulnerabilities
def detect_sql_injection(url):
    vulnerabilities = []
    try:
        # Analyze URL parameters
        vulnerabilities.extend(analyze_url_parameters(url))

        # Analyze headers
        vulnerabilities.extend(analyze_headers(url))

        # Analyze cookies
        vulnerabilities.extend(analyze_cookies(url))

        # Analyze HTML forms
        vulnerabilities.extend(analyze_forms(url))

    except Exception as e:
        print("Error occurred:", e)
    return vulnerabilities

# Function to analyze URL parameters for SQL injection
def analyze_url_parameters(url):
    vulnerabilities = []
    parsed_url = urlparse(url)
    query_params = parsed_url.query.split('&')
    
    for param in query_params:
        if '=' in param:
            param_name, param_value = param.split('=')
            fuzzed_params = fuzz_parameters(param_value)
            for fuzzed_param in fuzzed_params:
                test_url = url.replace(param_value, fuzzed_param)
                if check_injection(test_url):
                    vulnerabilities.append({
                        'endpoint': url,
                        'type': "SQL Injection in URL parameter",
                        'details': f"Parameter: {param_name}, Payload: {fuzzed_param}",
                        'mitigation': "Use parameterized queries or input validation to sanitize user input.",
                        'payload': fuzzed_param  # Include payload
                    })
        else:
            # Handle parameters without values
            fuzzed_params = fuzz_parameters(param)
            for fuzzed_param in fuzzed_params:
                test_url = url.replace(param, fuzzed_param)
                if check_injection(test_url):
                    vulnerabilities.append({
                        'endpoint': url,
                        'type': "SQL Injection in URL parameter",
                        'details': f"Parameter: {param}, Payload: {fuzzed_param}",
                        'mitigation': "Use parameterized queries or input validation to sanitize user input.",
                        'payload': fuzzed_param  # Include payload
                    })
    
    return vulnerabilities


# Function to analyze headers for SQL injection
def analyze_headers(url):
    vulnerabilities = []
    try:
        response = requests.head(url)
        response_headers = response.headers

        for header_name, header_value in response_headers.items():
            if contains_sql_keywords(header_value):
                vulnerabilities.append({
                    'endpoint': url,
                    'type': "SQL Injection in header",
                    'details': f"Header: {header_name}, Value: {header_value}",
                    'mitigation': "Ensure proper input validation and sanitization.",
                    'payload': header_value  # Include payload
                })

    except Exception as e:
        print("Error occurred during header analysis:", e)
    
    return vulnerabilities

# Function to analyze cookies for SQL injection
def analyze_cookies(url):
    vulnerabilities = []
    try:
        response = requests.get(url)
        cookies = response.cookies

        for cookie in cookies:
            # Check if the cookie value exhibits behavior indicative of Blind SQL Injection
            if is_blind_sql_injection(url, cookie.name, cookie.value):
                vulnerabilities.append({
                    'endpoint': url,
                    'type': "Blind SQL Injection in cookie",
                    'details': f"Cookie: {cookie.name}, Value: {cookie.value}",
                    'mitigation': "Ensure proper input validation and sanitization.",
                    'payload': cookie.value  # Include payload
                })

    except Exception as e:
        print("Error occurred during cookie analysis:", e)
    
    return vulnerabilities

# Function to check if the cookie value exhibits behavior indicative of Blind SQL Injection
def is_blind_sql_injection(url, cookie_name, cookie_value):
    try:
        # Example pattern to detect Blind SQL Injection (modify as needed based on application behavior)
        # For example, if the application takes longer to respond for certain payloads, that could indicate a Blind SQL Injection vulnerability
        payload = "' OR SLEEP(5) --"
        injected_cookie = cookie_value.replace("{payload}", payload)
        response_with_injection = requests.get(url, cookies={cookie_name: injected_cookie})
        response_without_injection = requests.get(url, cookies={cookie_name: cookie_value})
        return response_with_injection.elapsed.total_seconds() > response_without_injection.elapsed.total_seconds()
    except Exception as e:
        print("Error occurred during Blind SQL Injection check:", e)
        return False

# Function to analyze HTML forms for SQL injection, including login forms
def analyze_forms(url):
    vulnerabilities = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_url = form.get('action')
            form_method = form.get('method')
            form_inputs = form.find_all('input')
            
            params = {}
            for input_tag in form_inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name and input_type != 'submit':
                    params[input_name] = fuzz_parameters(input_name)
                    
            # Check if it's a login form
            if is_login_form(form):
                for param, payloads in params.items():
                    for payload in payloads:
                        # Construct the login request with the fuzzed parameter
                        login_data = {param: payload}
                        login_response = requests.post(form_url, data=login_data)
                        if 'error' in login_response.text.lower():
                            vulnerabilities.append({
                                'endpoint': url,
                                'type': "SQL Injection in login form",
                                'details': f"Parameter: {param}, Payload: {payload}",
                                'mitigation': "Use parameterized queries or input validation to sanitize user input.",
                                'payload': payload  # Include payload
                            })
            else:
                # Analyze other forms normally
                if form_method == 'get':
                    for param, payloads in params.items():
                        for payload in payloads:
                            new_url = f"{form_url}?{param}={payload}"
                            if check_injection(new_url):
                                vulnerabilities.append({
                                    'endpoint': url,
                                    'type': "SQL Injection in form (GET)",
                                    'details': f"Parameter: {param}, Payload: {payload}",
                                    'mitigation': "Use parameterized queries or input validation to sanitize user input.",
                                    'payload': payload  # Include payload
                                })
                elif form_method == 'post':
                    for param, payloads in params.items():
                        for payload in payloads:
                            data = {param: payload}
                            if check_injection(form_url, data=data):
                                vulnerabilities.append({
                                    'endpoint': url,
                                    'type': "SQL Injection in form (POST)",
                                    'details': f"Parameter: {param}, Payload: {payload}",
                                    'mitigation': "Use parameterized queries or input validation to sanitize user input.",
                                    'payload': payload  # Include payload
                                })
                        
    except Exception as e:
        print("Error occurred during form analysis:", e)
    
    return vulnerabilities

# Function to check if a form is a login form
def is_login_form(form):
    # Example: Check if form contains input fields for username and password
    username_input = form.find('input', {'name': 'username'})
    password_input = form.find('input', {'name': 'password'})
    return username_input is not None and password_input is not None

# Function to check for SQL injection
def check_injection(url, data=None):
    try:
        response = requests.get(url, data=data)
        if 'error' in response.text.lower():
            return True
    except Exception as e:
        pass
    return False

# Function to fuzz parameters
def fuzz_parameters(param_value):
    payloads = [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "' OR 1=1 /*",
        "' OR '1'='1' /*",
        "1'; DROP TABLE users; --",
        "1 AND 1=1",
        "1 AND 1=2",
        "1 OR 1=1",
        "1 OR 1=2",
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' OR 1=1",
        "' OR 1=2",
        "' AND 1=1",
        "' AND 1=2",
        "1; SELECT * FROM users;",
        "1 UNION SELECT 1,2,3 FROM users;",
        "1; SELECT password FROM users;",
        "1 UNION SELECT 1,username,password FROM users;",
    ]
    fuzzed_params = []
    for payload in payloads:
        fuzzed_param = urlencode({param_value: payload})
        fuzzed_params.append(fuzzed_param)
    return fuzzed_params

# Function to check if the string contains SQL keywords
def contains_sql_keywords(s):
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'FROM', 'WHERE', 'JOIN', 'OR', 'AND']
    for keyword in sql_keywords:
        if keyword in s.upper():
            return True
    return False



# Function to crawl the website and collect endpoints
def crawl_website(url, visited=None):
    if visited is None:
        visited = set()
    endpoints = set()
    
    # Avoid visiting the same URL multiple times
    if url in visited:
        return endpoints
    
    visited.add(url)
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                absolute_url = urljoin(url, href)
                if absolute_url.startswith(url):  # Only consider internal links
                    endpoints.add(absolute_url)
                    endpoints.update(crawl_website(absolute_url, visited))
    except Exception as e:
        print(f"Error occurred while crawling {url}: {e}")
    
    return endpoints

# Function to generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Function to send OTP via email
def send_otp_email(email, otp):
    subject = 'Login OTP'
    message = f"Your OTP is: {otp}"
    from_email = 'autoreply@litwebtech.com'  # Your email
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)

# Registration View
class RegisterView(View):
    def get(self, request):
        form = RegistrationForm()
        return render(request, 'register.html', {'form': form})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            # Check password strength
            if not self.is_strong_password(password):
                form.add_error('password', 'Password must be at least 8 characters long, include uppercase, lowercase, number, and special character.')
                return render(request, 'register.html', {'form': form})

            # Send OTP
            otp = generate_otp()
            request.session['pending_user_data'] = form.cleaned_data
            request.session['registration_otp'] = otp
            request.session['registration_otp_time'] = timezone.now().isoformat()
            send_otp_email(email, otp)

            return redirect('verify_registration_otp')

        return render(request, 'register.html', {'form': form})

    def is_strong_password(self, password):
        import re
        return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))
    
#verifyotpregistration
def verify_registration_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        stored_otp = request.session.get('registration_otp')
        otp_time_str = request.session.get('registration_otp_time')

        if entered_otp and stored_otp and otp_time_str:
            otp_time = datetime.fromisoformat(otp_time_str)
            if entered_otp == stored_otp and timezone.now() < otp_time + timedelta(minutes=5):
                data = request.session.get('pending_user_data')
                if data:
                    form = RegistrationForm(data)
                    if form.is_valid():
                        user = form.save(commit=False)
                        user.set_password(data['password'])
                        user.is_active = False  # Set as inactive
                        user.save()
                        Profile.objects.get_or_create(user=user)
                        request.session.pop('registration_otp', None)
                        request.session.pop('pending_user_data', None)
                        
                        # ✅ Success popup
                        messages.success(request, 'Account created successfully. Awaiting activation by the admin.')
                        return redirect('login')
            else:
                messages.error(request, 'Invalid or expired OTP.')

    return render(request, 'verify_registration_otp.html')





def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if the IP address is already blocked
        ip_address = request.META.get('REMOTE_ADDR')
        blocked_key = f'blocked_{ip_address}'
        if cache.get(blocked_key):
            return render(request, 'blocked.html')  # Display a blocked page

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if not user.is_active:
                return render(request, 'login.html', {
                    'error': 'Your account is pending Activation by admin. Please wait..',
                    'username': username,
                })

            auth_login(request, user)
            cache.delete(f'login_attempts_{username}')

            # Generate OTP and send via email
            otp = generate_otp()
            send_otp_email(user.email, otp)
            request.session['otp'] = otp
            request.session['otp_timestamp'] = timezone.now().isoformat()
            request.session['user_id'] = user.id

            return redirect('otp_verification')
        else:
            # Extra check for inactive user
            try:
                existing_user = User.objects.get(username=username)
                if existing_user.check_password(password) and not existing_user.is_active:
                    return render(request, 'login.html', {
                        'error': 'Your account is pending confirmation. Please check your email.',
                        'username': username,
                    })
            except User.DoesNotExist:
                pass

            # Increment attempt count and check if user should be blocked
            attempt_key = f'login_attempts_{username}'
            current_attempts = cache.get(attempt_key, 0)
            attempts_left = 5 - current_attempts - 1
            cache.set(attempt_key, current_attempts + 1, timeout=300)

            if attempts_left <= 0:
                cache.set(blocked_key, True, timeout=300)
                return render(request, 'blocked.html')

            return render(request, 'login.html', {
                'attempts_left': attempts_left,
                'username': username,
                'error': 'Invalid username or password.',
            })

    return render(request, 'login.html')


@login_required
def otp_verification(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp:
            stored_otp = request.session.get('otp')
            otp_timestamp_str = request.session.get('otp_timestamp')
            user_id = request.session.get('user_id')
            if stored_otp and otp_timestamp_str and user_id:
                otp_timestamp = datetime.fromisoformat(otp_timestamp_str)
                if entered_otp == stored_otp and timezone.now() < otp_timestamp + timedelta(minutes=5):
                    # Mark OTP as verified in session
                    request.session['otp_verified'] = True
                    del request.session['otp']
                    del request.session['otp_timestamp']
                    return redirect('dashboard')
                else:
                    attempt_key = f'otp_attempts_{user_id}'
                    attempts_left = 5 - cache.get(attempt_key, 0)
                    attempts_left -= 1
                    cache.set(attempt_key, cache.get(attempt_key, 0) + 1, timeout=600)

                    if attempts_left <= 0:
                        ip_address = request.META.get('REMOTE_ADDR')
                        blocked_key = f'blocked_{ip_address}'
                        cache.set(blocked_key, True, timeout=600)
                        return render(request, 'blocked.html')

                    error_message = 'Invalid OTP or OTP has expired. Please try again.'
                    return render(request, 'otp_verification.html', {'error': error_message, 'attempts_left': attempts_left})

    # If user tries to access OTP verification without logging in first
    if not request.session.get('otp'):
        return redirect('login')

    return render(request, 'otp_verification.html')






@login_required
@require_POST
def resend_otp(request):
    user = request.user
    otp = generate_otp()
    send_otp_email(user.email, otp)
    request.session['otp'] = otp
    request.session['otp_timestamp'] = timezone.now().isoformat()
    return JsonResponse({'success': True})



@login_required
def dashboard(request):
    # Ensure user has completed OTP verification
    if not request.session.get('otp_verified'):
        return redirect('otp_verification')
    return render(request, 'dashboard.html')

@login_required
def logout(request):
    auth_logout(request)
    # Clear the OTP verified session flag
    request.session.flush()
    return redirect('login')




def reset_password_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if email:
            try:
                user = User.objects.get(email=email)
                otp = generate_otp()
                request.session['reset_password_email'] = email
                request.session['reset_password_otp'] = otp
                request.session['reset_password_otp_time'] = timezone.now().isoformat()
                send_otp_email(email, otp)
                messages.success(request, 'An OTP has been sent to your email.')
                return redirect(reverse('verify_otp'))
            except User.DoesNotExist:
                messages.error(request, 'User with this email does not exist.')
    return render(request, 'reset_password_request.html')

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp:
            stored_otp = request.session.get('reset_password_otp')
            otp_timestamp_str = request.session.get('reset_password_otp_time')
            email = request.session.get('reset_password_email')

            if stored_otp and otp_timestamp_str and email:
                try:
                    otp_timestamp = datetime.fromisoformat(otp_timestamp_str)

                    if entered_otp == stored_otp and timezone.now() < otp_timestamp + timedelta(minutes=5):
                        # OTP is valid
                        request.session['otp_verified'] = True
                        request.session.pop('reset_password_otp', None)
                        request.session.pop('reset_password_otp_time', None)
                        return redirect('reset_password_confirm')

                    else:
                        # OTP is invalid or expired
                        attempt_key = f'otp_attempts_{email}'
                        attempts_left = 5 - cache.get(attempt_key, 0)
                        attempts_left -= 1
                        cache.set(attempt_key, cache.get(attempt_key, 0) + 1, timeout=600)

                        if attempts_left <= 0:
                            ip_address = request.META.get('REMOTE_ADDR')
                            blocked_key = f'blocked_{ip_address}'
                            cache.set(blocked_key, True, timeout=600)
                            return render(request, 'blocked.html')

                        messages.error(request, 'Invalid OTP or OTP has expired. Please try again.')
                        return render(request, 'verify_otp.html', {'attempts_left': attempts_left})

                except ValueError:
                    messages.error(request, 'An error occurred while processing the OTP. Please try again.')

    # If OTP session is not set
    if not request.session.get('reset_password_otp'):
        return redirect('reset_password_request')

    return render(request, 'verify_otp.html')

# otp password resend request
def resend_otp_password(request):
    email = request.session.get('reset_password_email')
    if email:
        otp = generate_otp()
        request.session['reset_password_otp'] = otp
        request.session['reset_password_otp_time'] = timezone.now().isoformat()
        send_otp_email(email, otp)
        messages.success(request, 'A new OTP has been sent to your email.')
    return redirect(reverse('verify_otp'))

def reset_password_confirm(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        email = request.session.get('reset_password_email')
        
        if password and confirm_password:
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'reset_password_confirm.html')

            if email:
                try:
                    user = User.objects.get(email=email)
                    user.set_password(password)
                    user.save()
                    messages.success(request, 'Password has been reset successfully.')
                    return redirect(reverse('login'))
                except User.DoesNotExist:
                    messages.error(request, 'User with this email does not exist.')
                    return redirect(reverse('reset_password_request'))
        else:
            messages.error(request, 'Please fill out both password fields.')
    
    return render(request, 'reset_password_confirm.html')


@method_decorator(login_required, name='dispatch')
class PaypalPaymentView(View):
    def get(self, request, *args, **kwargs):
        # Render a page with a checkout button
        return render(request, 'paypal_payment.html')

    def post(self, request, *args, **kwargs):
        amount = 1  # Example amount
        # Construct return and cancel URLs
        return_url = request.build_absolute_uri('/paypal_execute/')
        cancel_url = request.build_absolute_uri('/paypal_cancel/')
        
        status, payment_id, approval_url = make_paypal_payment(
            amount=amount, 
            currency="USD", 
            return_url=return_url, 
            cancel_url=cancel_url
        )
        
        if status:
            # Store payment ID in session for later verification
            request.session['payment_id'] = payment_id
            # Redirect the user to the PayPal approval URL
            return redirect(approval_url)
        else:
            return render(request, 'payment_failed.html', {'message': f"Payment creation failed: {str(approval_url)}"})

@login_required
def paypal_execute(request):
    payment_id = request.GET.get('paymentId')
    payer_id = request.GET.get('PayerID')
    
    if payment_id and payer_id:
        stored_payment_id = request.session.get('payment_id')
        if stored_payment_id and payment_id == stored_payment_id:
            if verify_paypal_payment(payment_id=payment_id, payer_id=payer_id):
                # Update user's premium status
                try:
                    profile = request.user.profile
                    profile.premium_status = True
                    profile.save()
                    del request.session['payment_id']
                    return redirect('dashboard')
                except Profile.DoesNotExist:
                    return render(request, 'payment_failed.html', {'message': "User profile not found."})
            else:
                return render(request, 'payment_failed.html', {'message': "Payment verification failed."})
    return render(request, 'payment_failed.html', {'message': "Payment ID or Payer ID missing."})

@login_required
def paypal_cancel(request):
    return render(request, 'payment_failed.html', {'message': "Payment was cancelled."})


@login_required
def payment_success(request):
    payment_id = request.GET.get('paymentId')
    payer_id = request.GET.get('PayerID')

    if payment_id and payer_id:
        stored_payment_id = request.session.get('payment_id')
        if stored_payment_id and payment_id == stored_payment_id:
            if verify_paypal_payment(payment_id=payment_id, payer_id=payer_id):
                profile, created = Profile.objects.get_or_create(user=request.user)
                profile.premium_status = True
                profile.save()
                del request.session['payment_id']
                return redirect('dashboard')
            else:
                return render(request, 'payment_failed.html', {'message': "Payment verification failed."})
    return render(request, 'payment_failed.html', {'message': "Payment ID or Payer ID missing."})

    

class PaypalValidatePaymentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        payment_id = request.data.get("payment_id")
        payment_status = verify_paypal_payment(payment_id=payment_id)
        if payment_status:
            return Response({"success": True, "msg": "Payment approved"}, status=200)
        else:
            return Response({"success": False, "msg": "Payment failed or cancelled"}, status=200)




# Payment Required View
def payment_required_view(request):
    return render(request, 'payment_required.html')





    