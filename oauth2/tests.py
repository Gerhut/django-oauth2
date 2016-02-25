from django.test import TestCase
from django.http import QueryDict
from django.contrib.auth import get_user_model

from uuid import UUID
from base64 import b64encode
from urllib.parse import urlsplit

from .models import Client, RedirectURI, AccessToken


class AuthorizationCodeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client',
                             grant_type=0)  # authorization_code
        cls._client.save()

        cls._redirect_uri = RedirectURI(client=cls._client,
                                        value='http://www.example.com/')
        cls._redirect_uri.save()

        User = get_user_model()
        cls._user = User.objects.create_user(username='TestUser')

    def testRequestToken(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': str(self._client),
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = str(self._client) + ':' + self._client.get_secret()
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'authorization_code',
            'code': redirect_query['code'],
            'redirect_uri': str(self._redirect_uri)
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        access_token = response.json()['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(access_token.client, self._client)
        self.assertEqual(access_token.user, self._user)


class ImplicitTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client', grant_type=1)  # implicit
        cls._client.save()

        cls._redirect_uri = RedirectURI(client=cls._client,
                                        value='http://www.example.com/')
        cls._redirect_uri.save()

        User = get_user_model()
        cls._user = User.objects.create_user(username='TestUser')

    def testRequestToken(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'token',
            'client_id': str(self._client),
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        access_token = redirect_query['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(access_token.client, self._client)
        self.assertEqual(access_token.user, self._user)


class PasswordTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client', grant_type=2)  # password
        cls._client.save()

        User = get_user_model()
        cls._password = 'DjangoOAuth2'
        cls._user = User.objects.create_user(username='TestUser',
                                             password=cls._password)

    def testRequestToken(self):
        authorization = str(self._client) + ':' + self._client.get_secret()
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': self._user.username,
            'password': self._password,
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        access_token = response.json()['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(access_token.client, self._client)
        self.assertEqual(access_token.user, self._user)


class ClientCredentialsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client',
                             grant_type=3)  # client_credentials
        cls._client.save()

    def testRequestToken(self):
        authorization = str(self._client) + ':' + self._client.get_secret()
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials'
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        access_token = response.json()['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(self._client, access_token.client)
        self.assertIsNone(access_token.user)
