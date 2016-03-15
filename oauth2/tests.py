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
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
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

    def testAnthorizeInvalidRequest(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'invalid_request')

    def testAnthorizeUnauthorizedClient(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': 'Dummy',
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'unauthorized_client')

    def testAnthorizeAccessDenied(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': 'http://dummy.example.com',
            'state': state
        })

        self.assertEqual(response.json()['error'], 'access_denied')

    def testAnthorizeUnsupportedResponseType(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'Dummy',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'unsupported_response_type')

    def testInvalidRequest(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'authorization_code',
            'code': redirect_query['code']
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'invalid_request')

    def testInvalidClient(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'authorization_code',
            'code': redirect_query['code'],
            'redirect_uri': str(self._redirect_uri)
        }, HTTP_AUTHORIZATION='Basic dummy')

        self.assertEqual(response.json()['error'], 'invalid_client')

    def testInvalidGrant(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'authorization_code',
            'code': 'dummy',
            'redirect_uri': str(self._redirect_uri)
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'invalid_grant')

    def testUnauthorizedClient(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials',
            'redirect_uri': str(self._redirect_uri)
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unauthorized_client')

    def testUnsupportedGrantType(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'code',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        redirect_uri = response['Location']
        redirect_query = QueryDict(urlsplit(redirect_uri).query)
        self.assertTrue(redirect_uri.startswith(str(self._redirect_uri)))
        self.assertEqual(redirect_query['state'], state)

        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'dummy',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unsupported_grant_type')


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
            'client_id': self._client.id.hex,
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

    def testAnthorizeInvalidRequest(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'token',
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'invalid_request')

    def testAnthorizeUnauthorizedClient(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'token',
            'client_id': 'Dummy',
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'unauthorized_client')

    def testAnthorizeAccessDenied(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'token',
            'client_id': self._client.id.hex,
            'redirect_uri': 'http://dummy.example.com',
            'state': state
        })

        self.assertEqual(response.json()['error'], 'access_denied')

    def testAnthorizeUnsupportedResponseType(self):
        state = 'test_state'
        self.client.force_login(self._user)
        response = self.client.get('/authorize', {
            'response_type': 'Dummy',
            'client_id': self._client.id.hex,
            'redirect_uri': str(self._redirect_uri),
            'state': state
        })

        self.assertEqual(response.json()['error'], 'unsupported_response_type')


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
        authorization = self._client.id.hex + ':' + self._client.secret.hex
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

    def testInvalidRequest(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': self._user.username,
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'invalid_request')

    def testInvalidClient(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': self._user.username,
            'password': self._password,
        }, HTTP_AUTHORIZATION='Basic Dummy')

        self.assertEqual(response.json()['error'], 'invalid_client')

    def testInvalidGrant(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': self._user.username,
            'password': 'Dummy',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'invalid_grant')

    def testUnauthorizedClient(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unauthorized_client')

    def testUnsupportedGrantType(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'Dummy',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unsupported_grant_type')


class ClientCredentialsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client',
                             grant_type=3)  # client_credentials
        cls._client.save()

    def testRequestToken(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials'
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        access_token = response.json()['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(access_token.client, self._client)
        self.assertIsNone(access_token.user)

    def testInvalidClient(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'client_credentials'
        }, HTTP_AUTHORIZATION='Basic Dummy')

        self.assertEqual(response.json()['error'], 'invalid_client')

    def testUnauthorizedClient(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'password',
            'username': 'dummy',
            'password': 'dummy',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unauthorized_client')

    def testUnsupportedGrantType(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'Dummy',
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        self.assertEqual(response.json()['error'], 'unsupported_grant_type')


class RefreshTokenTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._client = Client(name='Test Client',
                             grant_type=0)  # authorization_code
        cls._client.save()

        User = get_user_model()
        cls._user = User.objects.create_user(username='TestUser')

        cls._access_token = AccessToken(client=cls._client, user=cls._user)
        cls._access_token.save()

    def testRequestToken(self):
        authorization = self._client.id.hex + ':' + self._client.secret.hex
        authorization = b64encode(
            authorization.encode('ascii')).decode('ascii')
        response = self.client.post('/token', {
            'grant_type': 'refresh_token',
            'refresh_token': self._access_token.get_refresh_token()
        }, HTTP_AUTHORIZATION='Basic ' + authorization)

        access_token = response.json()['access_token']
        access_token = AccessToken.objects.get(id=UUID(hex=access_token))
        self.assertEqual(access_token.client, self._client)
        self.assertEqual(access_token.user, self._user)


# class GeneralErrorTest(TestCase):
#     @classmethod
#     def setUpTestData(cls):
#         cls._client = Client(name='Test Client',
#                              grant_type=3)  # client_credentials
#         cls._client.save()
#
#     def testInvalidRequest(self):
#         authorization = self._client.id.hex + ':' + self._client.secret.hex
#         authorization = b64encode(
#             authorization.encode('ascii')).decode('ascii')
#         response = self.client.post(
#             '/token', HTTP_AUTHORIZATION='Basic ' + authorization)
#
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.json()['error'], 'invalid_request')
#
#     def testInvalidClient(self):
#         response = self.client.post('/token', {
#             'grant_type': 'client_credentials'
#         })
#
#         self.assertEqual(response.status_code, 401)
#         self.assertEqual(response.json()['error'], 'invalid_client')
#         self.assertIn('WWW-Authenticate', response)
#
#         response = self.client.post('/token', {
#             'grant_type': 'client_credentials'
#         }, HTTP_AUTHORIZATION='Basic dummy')
#
#         self.assertEqual(response.status_code, 401)
#         self.assertEqual(response.json()['error'], 'invalid_client')
#         self.assertIn('WWW-Authenticate', response)
#
#     def testInvalidGrant(self):
#         response = self.client.post('/token', {
#             'grant_type': 'password',
#             'username': 'TestUser',
#             'password': 'DjangoOAuth2'
#         })
#
#         self.assertEqual(response.status_code, 401)
#         self.assertEqual(response.json()['error'], 'invalid_grant')
#         self.assertIn('WWW-Authenticate', response)
