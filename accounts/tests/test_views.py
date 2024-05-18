import json

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient


# ========== Tests for JWT Authentication Endpoints ==========
class JWTAuthenticationEndpointsTestCase(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='test2@example.com',
            password='password123'
        )
        self.user.is_email_verified = True
        self.user.save()
        self.refresh_token = None

    def test_token_obtain_pair(self):
        url = reverse('token_obtain_pair')
        data = {'email': self.user.email, 'password': 'password123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.refresh_token = response.data.get('refresh')

    def test_token_obtain_pair_invalid_credentials(self):
        url = reverse('token_obtain_pair')
        data = {'email': self.user.email, 'password': 'wrongpassword'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)

    def test_token_refresh(self):
        self.test_token_obtain_pair()
        url = reverse('token_refresh')
        data = {'refresh': self.refresh_token}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertNotIn('refresh', response.data)

    def test_token_refresh_invalid_token(self):
        data = {'refresh': 'invalid_token'}
        url = reverse('token_refresh')
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)


# ========== Tests for User Registration ==========
class RegisterViewTestCase(APITestCase):
    def test_successful_registration(self):
        url = reverse('register')
        data = {'email': 'test@example.com', 'password': 'UniquePass123', 'password2': 'UniquePass123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertIn('Check your email for activation link.', response.data['detail'])

    def test_invalid_registration(self):
        # Missing email field
        url = reverse('register')
        data = {'password': 'UniquePass123', 'password2': 'UniquePass123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)

        # Invalid email format
        data = {'email': 'invalid_email', 'password': 'UniquePass123', 'password2': 'UniquePass123'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 400)

        # Password too short
        data = {'email': 'test@example.com', 'password': 'pass', 'password2': 'pass'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 400)

        # Passwords do not match
        data = {'email': 'test@example.com', 'password': 'UniquePass123', 'password2': 'UniquePass1234'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)


class ChangePasswordViewTests(APITestCase):

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='test2@example.com',
            password='password'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.url = reverse('change_password')

    def test_change_password_success(self):
        data = {
            'old_password': 'password',
            'new_password': 'new_password123',
            'new_password2': 'new_password123'
        }
        response = self.client.post(self.url, data)
        self.user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['detail'], 'Your password has been successfully changed.')
        self.assertTrue(self.user.check_password('new_password123'))

    def test_change_password_invalid_old_password(self):
        data = {
            'old_password': 'wrong_password',
            'new_password': 'new_password123',
            'new_password2': 'new_password123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['detail'], 'Invalid old password.')
        self.assertTrue(self.user.check_password('password'))

    def test_change_password_invalid_data(self):
        data = {
            'old_password': 'password123',
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 400)
        self.assertIn('new_password', response.data)
        self.assertTrue(self.user.check_password('password'))

    def test_change_password_passwords_do_not_match(self):
        data = {
            'old_password': 'password',
            'new_password': 'new_password123',
            'new_password2': 'new_password1234'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.user.check_password('password'))

    def test_change_password_invalid_new_password(self):
        data = {
            'old_password': 'password',
            'new_password': 'password',
            'new_password2': 'password'
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.user.check_password('password'))

    def test_change_password_with_missing_data(self):
        data = {
            'old_password': 'password',
            'new_password': 'new_password123',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.user.check_password('password'))

# TODO: Add tests for ResetPasswordView and ResetPasswordConfirmView and ActivateAccountView
