import json

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext as _

import jwt
from jwt_auth import settings, exceptions
from jwt_auth.core import User
from jwt_auth.utils import get_authorization_header
from jwt_auth.utils import is_token_blacklisted


jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JSONWebTokenAuthMixin(object):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'
    payload = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        try:
            request.user, request.token = self.authenticate(request)
        except exceptions.AuthenticationFailed as e:
            response = JsonResponse({'errors': [str(e)]}, status=401)
            response['WWW-Authenticate'] = self.authenticate_header(request)
            return response
        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def get_jwt_value(request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if settings.JWT_AUTH_COOKIE:
                auth = request.COOKIES.get(settings.JWT_AUTH_COOKIE, None)
                if auth is not None:
                    return auth
            raise exceptions.AuthenticationFailed(_("Invalid authorization data."))

        if auth[0].lower().decode("utf-8") != auth_header_prefix:
            raise exceptions.AuthenticationFailed()

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed(
                _('Invalid Authorization header. No credentials provided.')
            )
        elif len(auth) > 2:
            raise exceptions.AuthenticationFailed(
                _('Invalid Authorization header. Credentials string should not contain spaces.')
            )

        return auth[1]

    def authenticate(self, request):
        jwt_value = JSONWebTokenAuthMixin.get_jwt_value(request)
        if jwt_value is not None and is_token_blacklisted(jwt_value):
            raise exceptions.AuthenticationFailed(_('Invalid Token!'))
        try:
            self.payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            raise exceptions.AuthenticationFailed(_('Signature has expired.'))
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed(_('Error decoding signature.'))

        user = self.authenticate_credentials(self.payload)

        return (user, jwt_value)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        try:
            user_id = jwt_get_user_id_from_payload(payload)
            if user_id:
                user = User.objects.get(pk=user_id, is_active=True)
            else:
                raise exceptions.AuthenticationFailed(_('Invalid payload'))
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid signature'))

        return user

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return 'JWT realm="{0}"'.format(self.www_authenticate_realm)
