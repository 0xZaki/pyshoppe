import hashlib
import time
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


class AccountActivationTokenGenerator:
    def make_token(self, user):
        timestamp = str(int(time.time()))
        user_id = urlsafe_base64_encode(force_bytes(user.pk))
        token_hash = self._make_hash_value(user, timestamp)
        return f"{user_id}.{timestamp}.{token_hash}"

    def _make_hash_value(self, user, timestamp):
        email = user.email
        return hashlib.sha256(f"{email}{timestamp}".encode()).hexdigest()

    def check_token(self, user, token):
        if not token:
            return False
        user_id, timestamp, token_hash = token.split('.')
        if not user_id or not timestamp or not token_hash:
            return False
        if user_id != urlsafe_base64_encode(force_bytes(user.pk)):
            return False
        if self._make_hash_value(user, timestamp) != token_hash:
            return False
        return True


account_activation_token = AccountActivationTokenGenerator()
