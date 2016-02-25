from django.test import TestCase
from django.http import QueryDict
from django.contrib.auth import get_user_model

from uuid import UUID
from base64 import b64encode
from urllib.parse import urlsplit

from .models import Client, AccessToken


class AuthorizationCodeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        redirect_uri = 'http://www.example.com/'
        client = Client(name='Test Client',
                        grant_type=0,  # authorization_code
                        redirect_uri=redirect_uri)
        client.save()
        cls.client_id = str(client)
        cls.client_secret = client.secret.hex
        cls.client_redirect_uri = redirect_uri

        User = get_user_model()
        username = 'TestUser'
        password = 'HelloOAuth2'
        user = User.objects.create_user(username=username, password=password)
        cls.user_id = user.id
        cls.user_username = username
        cls.user_password = password

    def testRequestToken(self):
        state = 'test_state'
        self.client.login(username=self.user_username,
                          password=self.user_password)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.client_redirect_uri,
            'state': state
        })
        redirect_parts = urlsplit(response['Location'])
        client_redirect_parts = urlsplit(self.client_redirect_uri)
        self.assertEqual(redirect_parts.scheme, client_redirect_parts.scheme)
        self.assertEqual(redirect_parts.netloc, client_redirect_parts.netloc)
        self.assertEqual(redirect_parts.path, client_redirect_parts.path)
        query_dict = QueryDict(redirect_parts.query)
        self.assertIn(state, query_dict['state'])

        authorization = self.client_id + ':' + self.client_secret
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        code = query_dict['code']
        response = self.client.post('/token', {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.client_redirect_uri
        }, HTTP_AUTHORIZATION='Basic ' + authorization)
        access_token = response.json()['access_token']
        access_token = UUID(hex=access_token)
        access_token = AccessToken.objects.get(id=access_token)
        client = access_token.client
        user = access_token.user
        self.assertEqual(self.client_id, str(client))
        self.assertEqual(self.user_id, user.id)


class ImplicitTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        redirect_uri = 'http://www.example.com/'
        client = Client(name='Test Client',
                        grant_type=1,  # implicit
                        redirect_uri=redirect_uri)
        client.save()
        cls.client_id = str(client)
        cls.client_redirect_uri = redirect_uri

        User = get_user_model()
        username = 'TestUser'
        password = 'HelloOAuth2'
        user = User.objects.create_user(username=username, password=password)
        cls.user_id = user.id
        cls.user_username = username
        cls.user_password = password

    def testRequestToken(self):
        state = 'test_state'
        self.client.login(username=self.user_username,
                          password=self.user_password)
        response = self.client.get('/authorize', {
            'response_type': 'token',
            'client_id': self.client_id,
            'redirect_uri': self.client_redirect_uri,
            'state': state
        })
        redirect_parts = urlsplit(response['Location'])
        client_redirect_parts = urlsplit(self.client_redirect_uri)
        self.assertEqual(redirect_parts.scheme, client_redirect_parts.scheme)
        self.assertEqual(redirect_parts.netloc, client_redirect_parts.netloc)
        self.assertEqual(redirect_parts.path, client_redirect_parts.path)
        query_dict = QueryDict(redirect_parts.query)
        self.assertIn(state, query_dict['state'])

        access_token = query_dict['access_token']
        access_token = UUID(hex=access_token)
        access_token = AccessToken.objects.get(id=access_token)
        client = access_token.client
        user = access_token.user
        self.assertEqual(self.client_id, str(client))
        self.assertEqual(self.user_id, user.id)


class PasswordTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        client = Client(name="Test Client",
                        grant_type=2,  # password
                        redirect_uri="http://www.example.com/")
        client.save()
        cls.client_id = str(client)
        cls.client_secret = client.secret.hex

        User = get_user_model()
        username = 'TestUser'
        password = 'HelloOAuth2'
        user = User.objects.create_user(username=username, password=password)
        cls.user_id = user.id
        cls.user_username = username
        cls.user_password = password

    def testRequestToken(self):
        authorization = self.client_id + ':' + self.client_secret
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': self.user_username,
            'password': self.user_password,
        }, HTTP_AUTHORIZATION='Basic ' + authorization)
        access_token = response.json()['access_token']
        access_token = UUID(hex=access_token)
        access_token = AccessToken.objects.get(id=access_token)
        client = access_token.client
        user = access_token.user
        self.assertEqual(self.client_id, str(client))
        self.assertEqual(self.user_id, user.id)


class ClientCredentialsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        client = Client(name="Test Client",
                        grant_type=3,  # client_credentials
                        redirect_uri="http://www.example.com/")
        client.save()
        cls.client_id = str(client)
        cls.client_secret = client.secret.hex

    def testRequestToken(self):
        authorization = self.client_id + ':' + self.client_secret
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials'
        }, HTTP_AUTHORIZATION='Basic ' + authorization)
        access_token = response.json()['access_token']
        access_token = UUID(hex=access_token)
        client = AccessToken.objects.get(id=access_token).client
        self.assertEqual(self.client_id, str(client))
