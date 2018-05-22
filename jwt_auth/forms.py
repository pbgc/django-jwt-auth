from calendar import timegm
from datetime import datetime

from django import forms
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

from jwt_auth import settings
from jwt_auth.compat import User


jwt_payload_handler = settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = settings.JWT_ENCODE_HANDLER
jwt_decode_handler = settings.JWT_DECODE_HANDLER
jwt_get_user_id_from_payload = settings.JWT_PAYLOAD_GET_USER_ID_HANDLER


class JSONWebTokenForm(forms.Form):
    password = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(JSONWebTokenForm, self).__init__(*args, **kwargs)

        # Dynamically add the USERNAME_FIELD to self.fields.
        self.fields[self.username_field] = forms.CharField()

    @property
    def username_field(self):
        try:
            return User.USERNAME_FIELD
        except AttributeError:
            return 'username'

    def clean(self):
        cleaned_data = super(JSONWebTokenForm, self).clean()
        credentials = {
            self.username_field: cleaned_data.get(self.username_field),
            'password': cleaned_data.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    raise forms.ValidationError(_('User account is disabled.'))

                payload = jwt_payload_handler(user)

                # Include original issued at time for a brand new token,
                # to allow token refresh
                if settings.JWT_ALLOW_REFRESH:
                    payload['iat'] = timegm(
                        datetime.utcnow().utctimetuple()
                    )

                self.object = {
                    'token': jwt_encode_handler(payload)
                }

                self.user = user

            else:
                raise forms.ValidationError(_('Unable to login with provided credentials.'))
        else:
            raise forms.ValidationError(_('Must include "username" and "password"'))
