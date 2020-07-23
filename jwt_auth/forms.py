from datetime import datetime

from django import forms
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

from jwt_auth import settings
from jwt_auth.core import User


class JSONWebTokenForm(forms.Form):
    password = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically add the USERNAME_FIELD to self.fields.
        self.fields[self.username_field] = forms.CharField()

    @property
    def username_field(self):
        try:
            return User.USERNAME_FIELD
        except AttributeError:
            return 'username'

    def clean(self):
        cleaned_data = super().clean()
        credentials = {
            self.username_field: cleaned_data.get(self.username_field),
            'password': cleaned_data.get('password')
        }
        if all(credentials.values()):
            user = authenticate(**credentials)
            if user:
                if not user.is_active:
                    raise forms.ValidationError(_('User account is disabled.'))
                cleaned_data["user"] = user
            else:
                raise forms.ValidationError(_('Unable to login with provided credentials.'))
        else:
            raise forms.ValidationError(_('Must include "username" and "password"'))
