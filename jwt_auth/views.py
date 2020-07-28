import json
from datetime import datetime, timedelta

from django.utils.translation import ugettext as _
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.contrib.auth.signals import user_logged_in

from jwt_auth import settings
from jwt_auth.forms import JSONWebTokenForm
from jwt_auth.mixins import JSONWebTokenAuthMixin
from jwt_auth.utils import blacklist_token

jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER
jwt_payload_handler = settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = settings.JWT_ENCODE_HANDLER


@method_decorator(csrf_exempt, name='dispatch')
class ObtainJSONWebToken(View):
    http_method_names = ['post']
    error_response_dict = {'errors': [_('Improperly formatted request')]}

    def post(self, request, *args, **kwargs):
        try:
            request_json = json.loads(request.body.decode("utf-8"))
        except ValueError:
            return JsonResponse({'errors': [_('Improperly formatted request')]}, status=400)

        form = JSONWebTokenForm(request_json)

        if not form.is_valid():
            return JsonResponse({'errors': form.errors}, status=400)

        user = form.cleaned_data["user"]
        payload = jwt_payload_handler(user)

        # Include original issued at time for a brand new token,
        # to allow token refresh
        if settings.JWT_ALLOW_REFRESH:
            payload['iat'] = datetime.utcnow().timestamp()

        token = jwt_encode_handler(payload)

        # put the user in the request
        # this is to enable login loging for example
        # wrapping this view with another by doing
        # response = obtain_jwt_token(request)
        # ..... log using request.user
        # return response
        request.user = user
        # Update last_login on sucessful authentication
        user_logged_in.send(sender=user.__class__, request=None, user=user)

        response = JsonResponse({
            'token': token,
            'expiresIn': settings.JWT_EXPIRATION_DELTA.total_seconds()
        })

        if settings.JWT_AUTH_COOKIE is not None:
            expiration = datetime.utcnow() + settings.JWT_EXPIRATION_DELTA
            response.set_cookie(
                settings.JWT_AUTH_COOKIE,
                token,
                max_age=None,
                expires=expiration,
                httponly=True,
                # samesite="Strict"
            )

        return response


obtain_jwt_token = ObtainJSONWebToken.as_view()


@method_decorator(csrf_exempt, name='dispatch')
class RefreshJSONWebToken(JSONWebTokenAuthMixin, View):
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        # Get and check 'iat'
        orig_iat = self.payload.get('iat')
        if orig_iat:
            # Verify expiration
            refresh_limit = settings.JWT_REFRESH_EXPIRATION_DELTA
            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 + refresh_limit.seconds)
            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = datetime.utcnow().timestamp()
            if now_timestamp > expiration_timestamp:
                return JsonResponse({'errors': _('Refresh has expired.')}, status=400)
        else:
            return JsonResponse({'errors': _('iat field is required.')}, status=400)

        new_payload = jwt_payload_handler(request.user)
        new_payload['iat'] = orig_iat

        token = jwt_encode_handler(new_payload)
        response = JsonResponse({
            'token': token,
            'expiresIn': settings.JWT_EXPIRATION_DELTA.total_seconds()
        })
        if settings.JWT_AUTH_COOKIE is not None:
            expiration = datetime.utcnow() + settings.JWT_EXPIRATION_DELTA
            response.set_cookie(
                settings.JWT_AUTH_COOKIE,
                token,
                max_age=None,
                expires=expiration,
                httponly=True
            )
        return response


refresh_jwt_token = RefreshJSONWebToken.as_view()


@method_decorator(csrf_exempt, name='dispatch')
class InvalidateJSONWebToken(View):
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        try:
            token = JSONWebTokenAuthMixin.get_jwt_value(request)
            if token is not None:
                blacklist_token(token)
        except Exception as e:
            print(e)
        response = JsonResponse({})
        if settings.JWT_AUTH_COOKIE is not None:
            response.delete_cookie(settings.JWT_AUTH_COOKIE)
        return response


invalidate_jwt_token = InvalidateJSONWebToken.as_view()
