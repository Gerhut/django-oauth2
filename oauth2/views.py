from django.http import QueryDict, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login

from base64 import b64decode
from uuid import UUID
from urllib.parse import urlsplit, urlunsplit

from .models import Client, Code, AccessToken


@require_http_methods(['POST'])
def token(request):

    class GrantError(Exception):
        def __init__(self, msg):
            super().__init__(msg)
            self.msg = msg

    # Authenticate Client by Basic Access Authentication
    try:
        auth = request.META['HTTP_AUTHORIZATION']
        (auth_scheme, auth_param) = auth.split(' ', 1)
        assert auth_scheme.lower() == 'basic'
        auth_param = b64decode(auth_param.encode('ascii')).decode('ascii')
        (client_id, client_secret) = auth_param.split(':', 1)
        client_id = UUID(hex=client_id)
        client_secret = UUID(hex=client_secret)
        client = Client.objects.get(id=client_id)
        assert client.secret == client_secret
    except (KeyError, ValueError, AssertionError, Client.DoesNotExist):
        response = JsonResponse({'error': 'invalid_client'}, status=401)
        response['WWW-Authenticate'] = 'Basic realm="Django OAuth2 Client"'
        return response

    # Grant an Access Token by Different Grant Type
    try:
        grant_type = request.POST['grant_type']
        if grant_type == 'authorization_code':
            code = request.POST['code']
            redirect_uri = request.POST['redirect_uri']

            if client.get_grant_type_display() != 'authorization_code':
                raise GrantError('unauthorized_client')

            try:
                code = UUID(hex=code)
                code = Code.objects.get(id=code)
                assert not code.is_expired()
                assert code.client == client
                assert code.redirect_uri == redirect_uri
            except (ValueError, Code.DoesNotExist, AssertionError):
                raise GrantError('invalid_grant')

            access_token = code.get_access_token()
        elif grant_type == 'password':
            username = request.POST['username']
            password = request.POST['password']

            if client.get_grant_type_display() != 'password':
                raise GrantError('unauthorized_client')

            user = authenticate(username=username, password=password)
            if user is None or not user.is_active:
                raise GrantError('invalid_grant')

            access_token = AccessToken(client=client, user=user)
            access_token.save()
        elif grant_type == 'client_credentials':
            if client.get_grant_type_display() != 'client_credentials':
                raise GrantError('unauthorized_client')

            access_token = AccessToken(client=client, user=None)
            access_token.save()
        elif grant_type == 'refresh_token':
            refresh_token = request.POST['refresh_token']

            if client.get_grant_type_display() != 'authorization_code':
                raise GrantError('unauthorized_client')
            try:
                refresh_token = UUID(hex=refresh_token)
                access_token = AccessToken.objects.get(
                    refresh_id=refresh_token)
                assert access_token.client == client
                assert not access_token.is_refresh_expired()
            except AccessToken.DoesNotExist:
                raise GrantError('invalid_grant')

            access_token = access_token.refresh()
        else:
            return JsonResponse({'error': 'unsupported_grant_type'},
                                status=400)
    except KeyError:
        return JsonResponse({'error': 'invalid_request'}, status=400)
    except GrantError as e:
        return JsonResponse({'error': e.msg}, status=400)

    return JsonResponse({
        'access_token': str(access_token),
        'token_type': 'bearer',
        'expires_in': access_token.client.access_token_expires_in,
        'refresh_token': access_token.get_refresh_token(),
    })


@require_http_methods(['GET', 'POST'])
def authorize(request):

    def login_page(notice=None):
        return render(request, 'login.html', {
            'name': client.name,
            'notice': notice,
        })

    def redirect_back(query):
        parts = urlsplit(redirect_uri)
        origin_query = QueryDict(parts.query, mutable=True)
        origin_query.update(query)
        if state is not None:
            origin_query.appendlist('state', state)
        uri = urlunsplit(parts._replace(query=origin_query.urlencode()))
        return redirect(uri)

    def error(error):
        if redirect_uri is None:
            return JsonResponse({'error': error}, status=400)
        return redirect_back({'error': error})

    redirect_uri = None
    state = request.GET.get('state')

    # Client & Response Type Verify
    try:
        response_type = request.GET['response_type']
        client_id = request.GET['client_id']
        client_id = UUID(hex=client_id)
        client = Client.objects.get(id=client_id)
        grant_type = client.get_grant_type_display()
        assert response_type in ('code', 'token')
    except KeyError:
        return error('invalid_request')
    except (ValueError, Client.DoesNotExist):
        return error('unauthorized_client')
    except AssertionError:
        return error('unsupported_response_type')

    try:
        assert (grant_type == 'authorization_code' and
                response_type == 'code' or
                grant_type == 'implicit' and
                response_type == 'token')
    except AssertionError:
        return error('unauthorized_client')

    # Redirect URI Verify
    try:
        redirect_uri = request.GET['redirect_uri']
        assert client.redirecturi_set.filter(value=redirect_uri).count() > 0
    except KeyError:
        return error('invalid_request')
    except AssertionError:
        redirect_uri = None
        return error('access_denied')

    # User login
    if request.method == 'POST':
        try:
            username = request.POST['username']
            password = request.POST['password']
        except KeyError:
            return error('invalid_request')

        user = authenticate(username=username, password=password)
        if user is None or not user.is_active:
            return login_page('Invalid username or password.')
        login(request, user)
    else:  # Request method is GET
        user = request.user
        if not user.is_authenticated():
            return login_page()

    # Response
    if response_type == 'code':
        code = Code(client=client, user=request.user,
                    redirect_uri=redirect_uri)
        code.save()
        return redirect_back({'code': code.id})
    elif response_type == 'token':
        access_token = AccessToken(client=client, user=request.user)
        access_token.save()
        return redirect_back({
            'access_token': str(access_token),
            'token_type': 'bearer',
            'expires_in': access_token.client.access_token_expires_in,
        })
