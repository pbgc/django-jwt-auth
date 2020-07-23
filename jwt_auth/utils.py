from datetime import datetime
import importlib

from django.contrib.auth import get_user_model

try:
    import redis
except ImportError:
    redis = None

import jwt

from . import settings


def blacklist_token(token):
    if redis is not None:
        try:
            r = redis.Redis(
                host=settings.JWT_REDIS_HOST,
                port=settings.JWT_REDIS_PORT,
                db=settings.JWT_REDIS_DB
            )
            r.setex(
                token,
                settings.JWT_EXPIRATION_DELTA,
                value="EXPIRED"
            )
        except Exception as e:
            print(e)


def is_token_blacklisted(token):
    if redis is not None:
        try:
            r = redis.Redis(
                host=settings.JWT_REDIS_HOST,
                port=settings.JWT_REDIS_PORT,
                db=settings.JWT_REDIS_DB
            )
            return r.get(token) is not None
        except Exception as e:
            print(e)
    return False


def jwt_payload_handler(user):

    try:
        username = user.get_username()
    except AttributeError:
        username = user.username

    try:
        username_field = get_user_model().USERNAME_FIELD
    except AttributeError:
        username_field = 'username'

    payload = {
        "user_id": user.pk,
        username_field: username,
        "exp": datetime.utcnow() + settings.JWT_EXPIRATION_DELTA
    }

    if hasattr(user, 'email'):
        payload['email'] = user.email

    if settings.JWT_AUDIENCE is not None:
        payload['aud'] = settings.JWT_AUDIENCE

    if settings.JWT_ISSUER is not None:
        payload['iss'] = settings.JWT_ISSUER

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    user_id = payload.get('user_id')
    return user_id


def jwt_encode_handler(payload):
    key = settings.JWT_PRIVATE_KEY or settings.JWT_SECRET_KEY
    return jwt.encode(
        payload,
        key,
        settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):

    options = {
        'verify_exp': settings.JWT_VERIFY_EXPIRATION,
    }
    key = settings.JWT_PUBLIC_KEY or settings.JWT_SECRET_KEY
    return jwt.decode(
        token,
        key,
        settings.JWT_VERIFY,
        options=options,
        leeway=settings.JWT_LEEWAY,
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
        algorithms=[settings.JWT_ALGORITHM]
    )


def import_from_string(val):
    """
    Attempt to import a class from a string representation.

    From: https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/settings.py
    """
    try:
        # Nod to tastypie's use of importlib.
        parts = val.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        msg = "Could not import '%s' for setting. %s: %s." % (val, e.__class__.__name__, e)
        raise ImportError(msg)


def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.
    From: https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/authentication.py
    """
    auth = request.META.get('HTTP_AUTHORIZATION', b'')

    if isinstance(auth, type('')):
        # Work around django test client oddness
        auth = auth.encode('iso-8859-1')

    return auth
