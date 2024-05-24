import hashlib
import hmac
import os

from django.utils.crypto import get_random_string


def get_state():
    private_key = os.environ.get('GOOGLE_STATE_SECRET')
    state = get_random_string(32)
    signature = hmac.new(private_key.encode(), msg=state.encode(), digestmod=hashlib.sha256).digest().hex()
    return f'{state}.{signature}'


def validate_state(state):
    private_key = os.environ.get('GOOGLE_STATE_SECRET')
    state, signature = state.split('.')
    expected_signature = hmac.new(private_key.encode(), msg=state.encode(), digestmod=hashlib.sha256).digest().hex()
    if signature == expected_signature:
        return True
    return False
