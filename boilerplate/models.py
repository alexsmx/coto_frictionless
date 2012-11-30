from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import ndb
from lib import utils
from boilerplate import config

class User(User):
    """
    Universal user model. Can be used with App Engine's default users API,
    own auth or third party authentication methods (OpenID, OAuth etc).
    based on https://gist.github.com/kylefinley
    """

    #: Creation date.
    created = ndb.DateTimeProperty(auto_now_add=True)
    #: Modification date.
    updated = ndb.DateTimeProperty(auto_now=True)
    #: User defined unique name, also used as key_name.
    # Not used by OpenID
    username = ndb.StringProperty()
    #: User Name
    name = ndb.StringProperty()
    #: User Last Name
    last_name = ndb.StringProperty()
    #: User email
    email = ndb.StringProperty()
    #: Hashed password. Only set for own authentication.
    # Not required because third party authentication
    # doesn't use password.
    password = ndb.StringProperty()
    #: User Country
    country = ndb.StringProperty()
    #: Account activation verifies email
    activated = ndb.BooleanProperty(default=False)
    #: Referred Events
    events = ndb.KeyProperty(repeated=True)
    #: Paypalemail account
    paypalemail = ndb.StringProperty()
    #: Paypalemail confirmation
    paypalemailconfirmationtoken = ndb.StringProperty()
    #: Paypalemail confirmed
    paypalemailconfirmed=ndb.StringProperty()
    
    @classmethod
    def get_by_email(cls, email):
        """Returns a user object based on an email.

        :param email:
            String representing the user email. Examples:

        :returns:
            A user object.
        """
        return cls.query(cls.email == email).get()

    @classmethod
    def create_resend_token(cls, user_id):
        entity = cls.token_model.create(user_id, 'resend-activation-mail')
        return entity.token

    @classmethod
    def validate_resend_token(cls, user_id, token):
        return cls.validate_token(user_id, 'resend-activation-mail', token)

    @classmethod
    def delete_resend_token(cls, user_id, token):
        cls.token_model.get_key(user_id, 'resend-activation-mail', token).delete()

    def get_social_providers_names(self):
        social_user_objects = SocialUser.get_by_user(self.key)
        result = []
#        import logging
        for social_user_object in social_user_objects:
#            logging.error(social_user_object.extra_data['screen_name'])
            result.append(social_user_object.provider)
        return result

    def get_social_providers_info(self):
        providers = self.get_social_providers_names()
        result = {'used': [], 'unused': []}
        for k,v in SocialUser.PROVIDERS_INFO.items():
            if k in providers:
                result['used'].append(v)
            else:
                result['unused'].append(v)
        return result


class LogVisit(ndb.Model):
    user = ndb.KeyProperty(kind=User)
    uastring = ndb.StringProperty()
    ip = ndb.StringProperty()
    timestamp = ndb.StringProperty()


class LogEmail(ndb.Model):
    sender = ndb.StringProperty(
        required=True)
    to = ndb.StringProperty(
        required=True)
    subject = ndb.StringProperty(
        required=True)
    body = ndb.TextProperty()
    when = ndb.DateTimeProperty()


class SocialUser(ndb.Model):
    PROVIDERS_INFO = { # uri is for OpenID only (not OAuth)
        # 'google': {'name': 'google', 'label': 'Google', 'uri': 'gmail.com'},
        'facebook': {'name': 'facebook', 'label': 'Facebook', 'uri': ''},
        # 'linkedin': {'name': 'linkedin', 'label': 'LinkedIn', 'uri': ''},
        # 'myopenid': {'name': 'myopenid', 'label': 'MyOpenid', 'uri': 'myopenid.com'},
        # 'twitter': {'name': 'twitter', 'label': 'Twitter', 'uri': ''},
        # 'yahoo': {'name': 'yahoo', 'label': 'Yahoo!', 'uri': 'yahoo.com'},
    }

    user = ndb.KeyProperty(kind=User)
    provider = ndb.StringProperty()
    uid = ndb.StringProperty()
    extra_data = ndb.JsonProperty()
    #: Authentication token
    auth_token=ndb.StringProperty()
    #: Authentication token expires
    expires=ndb.IntegerProperty()
    #: Time when auth token was requested, in order to add the number of seconds 
    auth_time_request=ndb.DateTimeProperty(auto_now=True)
    #: Url to thumbnail of image (in case of Facebook)
    profile_picture_url=ndb.StringProperty()

    @classmethod
    def get_by_user(cls, user):
        return cls.query(cls.user == user).fetch()

    @classmethod
    def get_by_user_and_provider(cls, user, provider):
        return cls.query(cls.user == user, cls.provider == provider).get()

    @classmethod
    def get_by_provider_and_uid(cls, provider, uid):
        return cls.query(cls.provider == provider, cls.uid == uid).get()

    @classmethod
    def check_unique_uid(cls, provider, uid):
        # pair (provider, uid) should be unique
        test_unique_provider = cls.get_by_provider_and_uid(provider, uid)
        if test_unique_provider is not None:
            return False
        else:
            return True
    
    @classmethod
    def check_unique_user(cls, provider, user):
        # pair (user, provider) should be unique
        test_unique_user = cls.get_by_user_and_provider(user, provider)
        if test_unique_user is not None:
            return False
        else:
            return True

    @classmethod
    def check_unique(cls, user, provider, uid):
        # pair (provider, uid) should be unique and pair (user, provider) should be unique
        return cls.check_unique_uid(provider, uid) and cls.check_unique_user(provider, user)
    
    @staticmethod
    def open_id_providers():
        return [k for k,v in SocialUser.PROVIDERS_INFO.items() if v['uri']]


class PagoOxxo(ndb.Model):
    usuario = ndb.StringProperty()
    referencia= ndb.StringProperty()
    dias_vigencia= ndb.StringProperty()
    monto= ndb.StringProperty()
    url_respuesta= ndb.StringProperty()
    cliente= ndb.StringProperty()
    formato= ndb.StringProperty()
    email= ndb.StringProperty()
    sendpdf= ndb.StringProperty()
    codigo_barras= ndb.StringProperty()
    resp_referencia= ndb.StringProperty()
    resp_fecha_vigencia= ndb.StringProperty()
    resp_monto= ndb.StringProperty()
    resp_path_img= ndb.StringProperty()
    resp_plaza= ndb.StringProperty()
    resp_tienda= ndb.StringProperty()
    resp_fecha= ndb.StringProperty()
    resp_hora= ndb.StringProperty()
    resp_cb= ndb.StringProperty()
    resp_ref2= ndb.StringProperty()
    resp_monto2= ndb.StringProperty()
    resp_ref_externa= ndb.StringProperty()
    resp_flag= ndb.StringProperty()
    resp_bc_img=ndb.BlobProperty()


class ItemEvent(ndb.Model):
    user=ndb.KeyProperty(kind=User)
    temp_id= ndb.StringProperty()
    tipo_evento = ndb.StringProperty()
    fecha_evento = ndb.StringProperty()
    titulo_evento=ndb.StringProperty()
    descripcion_evento=ndb.StringProperty()
    meta_evento=ndb.StringProperty()
    formato_contribucion_evento= ndb.StringProperty()
    monto_contribucion_evento=ndb.StringProperty()
    image_url=ndb.StringProperty()
    visible=ndb.BooleanProperty(default=True)
    recolectado=ndb.FloatProperty(default=0)
    porcentaje_recolectado=ndb.FloatProperty(default=0)
    participantes= ndb.StringProperty(repeated=True)
    imagenes_participantes= ndb.StringProperty(repeated=True)
    facebook_post_ids=ndb.StringProperty(repeated=True)
    nombre_organizador=ndb.StringProperty()

    def getstrkey(self):
        return str(self.key.id())

    def gethashkey(self):
        return str(utils.hashing(self.key.id(), config.salt))

class PagoTC(ndb.Model):
    user=ndb.KeyProperty(kind=User)
    evento=ndb.KeyProperty(kind=ItemEvent)
    bwuser=ndb.StringProperty()
    bwid=ndb.StringProperty()
    bwreferencia=ndb.StringProperty()
    bwdate=ndb.StringProperty()
    bwcard=ndb.StringProperty()
    bwresponse=ndb.StringProperty()
    bwcode_auth=ndb.StringProperty()
    bwmonto=ndb.StringProperty()
    bwclient=ndb.StringProperty()

class PagoOxxo(ndb.Model):
    usuario = ndb.StringProperty()
    referencia= ndb.StringProperty()
    dias_vigencia= ndb.StringProperty()
    monto= ndb.StringProperty()
    url_respuesta= ndb.StringProperty()
    cliente= ndb.StringProperty()
    formato= ndb.StringProperty()
    email= ndb.StringProperty()
    sendpdf= ndb.StringProperty()
    codigo_barras= ndb.StringProperty()
    resp_referencia= ndb.StringProperty()
    resp_fecha_vigencia= ndb.StringProperty()
    resp_monto= ndb.StringProperty()
    resp_path_img= ndb.StringProperty()
    resp_plaza= ndb.StringProperty()
    resp_tienda= ndb.StringProperty()
    resp_fecha= ndb.StringProperty()
    resp_hora= ndb.StringProperty()
    resp_cb= ndb.StringProperty()
    resp_ref2= ndb.StringProperty()
    resp_monto2= ndb.StringProperty()
    resp_ref_externa= ndb.StringProperty()
    resp_flag= ndb.StringProperty()
    resp_bc_img=ndb.BlobProperty()

class ConfirmPagoOxxo(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    parametros=ndb.TextProperty()
    
class ConfirmPagoTC(ndb.Model):
    created= ndb.DateTimeProperty(auto_now_add=True)
    parametros=ndb.StringProperty()

class ImportantErrors(ndb.Model):
    created= ndb.DateTimeProperty(auto_now_add=True)
    error=ndb.StringProperty()
    module=ndb.StringProperty()

class PayPalRequest(ndb.Model):
    user=ndb.KeyProperty(kind=User)
    evento=ndb.KeyProperty(kind=ItemEvent)
    created=ndb.DateTimeProperty(auto_now_add=True)
    modified= ndb.DateTimeProperty(auto_now=True)
    paypalResponseString=ndb.TextProperty()
    confirmedPay=ndb.StringProperty()
    confirmedPayResponseString=ndb.TextProperty()
    paypalKey=ndb.StringProperty()
    amount=ndb.StringProperty()

class registerInteraction(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    parametros=ndb.TextProperty()

