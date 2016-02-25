from django.db import models
from django.conf import settings
from django.utils import timezone

from uuid import uuid4


class Scope(models.Model):
    name = models.CharField(max_length=8, primary_key=True)

    def __str__(self):
        return self.name


class Client(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4)
    secret = models.UUIDField(default=uuid4)
    name = models.CharField(max_length=16)
    redirect_uri = models.URLField()
    scopes = models.ManyToManyField(Scope)
    grant_type = models.PositiveSmallIntegerField(choices=(
        (0, 'authorization_code'),
        (1, 'implicit'),
        (2, 'password'),
        (3, 'client_credentials')
    ), default=0)
    code_expires_in = models.PositiveIntegerField(default=300)
    access_token_expires_in = models.PositiveIntegerField(default=604800)
    refresh_token_expires_in = models.PositiveIntegerField(default=2592000)

    def __str__(self):
        return self.id.hex

    def get_secret(self):
        return self.secret.hex

    def has_scopes(self, scopes):
        return len(scopes) == self.scopes.filter(pk__in=scopes).count()


class Code(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4)
    client = models.ForeignKey(Client, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    redirect_uri = models.URLField()
    created = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return self.id.hex

    def is_expired(self):
        seconds = (timezone.now() - self.created).total_seconds()
        return seconds > self.client.code_expires_in

    def get_access_token(self):
        self.delete()
        access_token = AccessToken(client=self.client, user=self.user)
        access_token.save()
        return access_token


class AccessToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4)
    client = models.ForeignKey(Client, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True)
    refresh_id = models.UUIDField(unique=True, default=uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True, editable=False)

    def __str__(self):
        return self.id.hex

    def get_refresh_token(self):
        return self.refresh_id.hex

    def is_expired(self):
        seconds = (timezone.now() - self.created).total_seconds()
        return seconds > self.client.access_token_expires_in

    def is_refresh_expires(self):
        seconds = (timezone.now() - self.created).total_seconds()
        return seconds > self.client.refresh_token_expires_in

    def refresh(self):
        self.delete()
        access_token = AccessToken(
            client=self.client,
            user=self.user,
            refresh_id=self.refresh_id)
        access_token.save()
        return access_token
