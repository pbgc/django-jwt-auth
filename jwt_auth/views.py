from datetime import datetime, timedelta
from calendar import timegm

from django.utils.translation import ugettext as _
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.core.serializers.json import DjangoJSONEncoder

from jwt_auth import settings
from jwt_auth.compat import json, smart_text
from jwt_auth.forms import JSONWebTokenForm
from jwt_auth.mixins import JSONWebTokenAuthMixin

jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER
jwt_payload_handler = settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = settings.JWT_ENCODE_HANDLER


class BaseJSONWebToken(object):
    json_encoder_class = DjangoJSONEncoder

    def render_response(self, context_dict):
        json_context = json.dumps(context_dict, cls=self.json_encoder_class)
        return HttpResponse(json_context, content_type='application/json')

    def render_bad_request_response(self, error_dict=None):
        if error_dict is None:
            error_dict = self.error_response_dict

        json_context = json.dumps(error_dict, cls=self.json_encoder_class)

        return HttpResponseBadRequest(json_context, content_type='application/json')


class ObtainJSONWebToken(BaseJSONWebToken, View):
    http_method_names = ['post']
    error_response_dict = {'errors': [_('Improperly formatted request')]}

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ObtainJSONWebToken, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        try:
            request_json = json.loads(smart_text(request.body))
        except ValueError:
            return self.render_bad_request_response()

        form = JSONWebTokenForm(request_json)

        if not form.is_valid():
            return self.render_bad_request_response({'errors': form.errors})

        return self.render_response({
            'token': form.object['token'],
            'expiresIn': settings.JWT_EXPIRATION_DELTA.total_seconds()
        })


obtain_jwt_token = ObtainJSONWebToken.as_view()


class RefreshJSONWebToken(JSONWebTokenAuthMixin, BaseJSONWebToken, View):
    http_method_names = ['post']

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(RefreshJSONWebToken, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Get and check 'orig_iat'
        orig_iat = self.payload.get('orig_iat')
        if orig_iat:
            # Verify expiration
            refresh_limit = settings.JWT_REFRESH_EXPIRATION_DELTA
            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 + refresh_limit.seconds)
            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())
            if now_timestamp > expiration_timestamp:
                return self.render_bad_request_response({'errors': _('Refresh has expired.')})
        else:
            return self.render_bad_request_response({'errors': _('orig_iat field is required.')})

        new_payload = jwt_payload_handler(request.user)
        new_payload['orig_iat'] = orig_iat

        return self.render_response({
            'token': jwt_encode_handler(new_payload),
            'expiresIn': settings.JWT_EXPIRATION_DELTA.total_seconds()
        })


refresh_jwt_token = RefreshJSONWebToken.as_view()
