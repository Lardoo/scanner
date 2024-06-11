import requests
import json
import logging
from decouple import config
from django.conf import settings

logger = logging.getLogger(__name__)

def make_paypal_payment(amount, currency, return_url, cancel_url):
    # Set up PayPal API credentials
    client_id = config("PAYPAL_ID")
    secret = config("PAYPAL_SECRET")
    url = config("PAYPAL_BASE_URL")

    # Set up API endpoints
    token_url = f'{url}/v1/oauth2/token'
    payment_url = f'{url}/v1/payments/payment'

    # Request an access token
    token_payload = {'grant_type': 'client_credentials'}
    token_headers = {'Accept': 'application/json', 'Accept-Language': 'en_US'}
    token_response = requests.post(token_url, auth=(client_id, secret), data=token_payload, headers=token_headers)

    if token_response.status_code != 200:
        error_message = token_response.json().get('error_description', 'Failed to authenticate with PayPal API')
        logger.error("Failed to authenticate with PayPal API: %s", error_message)
        return False, error_message, None

    access_token = token_response.json().get('access_token')

    # Create payment payload
    payment_payload = {
        'intent': 'sale',
        'payer': {'payment_method': 'paypal'},
        'transactions': [{
            'amount': {'total': str(amount), 'currency': currency},
            'description': 'Vulnvision scan & protect'
        }],
        'redirect_urls': {
            'return_url': return_url,
            'cancel_url': cancel_url
        }
    }

    # Create payment request
    payment_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    payment_response = requests.post(payment_url, data=json.dumps(payment_payload), headers=payment_headers)

    if payment_response.status_code != 201:
        error_message = payment_response.json().get('message', 'Failed to create PayPal payment')
        logger.error("Failed to create PayPal payment: %s", error_message)
        return False, error_message, None

    payment_id = payment_response.json().get('id')
    approval_url = next((link['href'] for link in payment_response.json().get('links', []) if link.get('rel') == 'approval_url'), None)

    if not approval_url:
        logger.error("Approval URL not found in PayPal payment response.")
        return False, 'Approval URL not found in PayPal payment response.', None

    return True, payment_id, approval_url

def verify_paypal_payment(payment_id, payer_id):
    # Set up PayPal API credentials
    client_id = config("PAYPAL_ID")
    secret = config("PAYPAL_SECRET")
    url = config("PAYPAL_BASE_URL")

    # Set up API endpoints
    token_url = f'{url}/v1/oauth2/token'
    execute_url = f'{url}/v1/payments/payment/{payment_id}/execute'

    # Request an access token
    token_payload = {'grant_type': 'client_credentials'}
    token_headers = {'Accept': 'application/json', 'Accept-Language': 'en_US'}
    token_response = requests.post(token_url, auth=(client_id, secret), data=token_payload, headers=token_headers)

    if token_response.status_code != 200:
        logger.error('Failed to authenticate with PayPal API.')
        return False

    access_token = token_response.json().get('access_token')

    # Execute payment payload
    execute_payload = {'payer_id': payer_id}
    execute_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    execute_response = requests.post(execute_url, data=json.dumps(execute_payload), headers=execute_headers)

    if execute_response.status_code != 200:
        logger.error('Failed to execute PayPal payment: %s', execute_response.text)
        return False

    payment_status = execute_response.json().get('state')
    return payment_status == 'approved'
