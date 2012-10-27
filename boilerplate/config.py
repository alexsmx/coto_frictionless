app_name = "WishFan: Crowdfunding de tus Regalos y Eventos."

webapp2_config = {}
webapp2_config['webapp2_extras.sessions'] = {
    'secret_key': 'ASDLFQWREQPOIUQWEROUQPWOIUWER',
}
webapp2_config['webapp2_extras.auth'] = {
    'user_model': 'boilerplate.models.User',
    'cookie_name': 'session_name'
}
webapp2_config['webapp2_extras.jinja2'] = {
    'template_path': ['templates','boilerplate/templates'],
    'environment_args': {'extensions': ['jinja2.ext.i18n']},
}
webapp2_config['webapp2_extras.i18n'] = {
    'default_locale': 'es_ES',
}


# the default language code for the application.
# should match whatever language the site uses when i18n is disabled
app_lang = 'es'

# Locale code = <language>_<territory> (ie 'en_US')
# to pick locale codes see http://cldr.unicode.org/index/cldr-spec/picking-the-right-language-code
# also see http://www.sil.org/iso639-3/codes.asp
# Language codes defined under iso 639-1 http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
# Territory codes defined under iso 3166-1 alpha-2 http://en.wikipedia.org/wiki/ISO_3166-1
# disable i18n if locales array is empty or None
#locales = ['en_US', 'es_ES', 'it_IT', 'zh_CN', 'id_ID', 'fr_FR', 'de_DE']
locales = ['es_ES']
contact_sender = "alexsmx@gmail.com"
contact_recipient = "alexsmx@gmail.com"

# Password AES Encryption Parameters
aes_key = "12_24_32_BYTES_KEY_FOR_PASSWORDS"
salt = "FASDLJASFDSDFPOIOUPOUPOUIPOIU"

# get your own consumer key and consumer secret by registering at https://dev.twitter.com/apps
# callback url must be: http://[YOUR DOMAIN]/login/twitter/complete
twitter_consumer_key = 'PUT_YOUR_TWITTER_CONSUMER_KEY_HERE'
twitter_consumer_secret = 'PUT_YOUR_TWITTER_CONSUMER_SECRET_HERE'

#Facebook Login
# get your own consumer key and consumer secret by registering at https://developers.facebook.com/apps
#Very Important: set the site_url= your domain in the application settings in the facebook app settings page
# callback url must be: http://[YOUR DOMAIN]/login/facebook/complete
_FbApiKey = 'PUT_YOUR_FACEBOOK_PUBLIC_KEY_HERE'
_FbSecret = 'PUT_YOUR_FACEBOOK_PUBLIC_KEY_HERE'

#Linkedin Login
#Get you own api key and secret from https://www.linkedin.com/secure/developer
linkedin_api = 'PUT_YOUR_LINKEDIN_PUBLIC_KEY_HERE'
linkedin_secret = 'PUT_YOUR_LINKEDIN_PUBLIC_KEY_HERE'

# get your own recaptcha keys by registering at http://www.google.com/recaptcha/
captcha_public_key = "6LfPQNYSAAAAAIhbEU_9w3CTNBkMkxQjzA2zv_xT"
captcha_private_key = "6LfPQNYSAAAAAASrXjTU8szgd8RB0w7TFUpb2Phc"

# Leave blank "google_analytics_domain" if you only want Analytics code
google_analytics_domain = "wishfan.com"
google_analytics_code = "UA-34610494-1"

error_templates = {
    403: 'errors/default_error.html',
    404: 'errors/default_error.html',
    500: 'errors/default_error.html',
}

# Enable Federated login (OpenID and OAuth)
# Google App Engine Settings must be set to Authentication Options: Federated Login
enable_federated_login = True

# jinja2 base layout templates
base_layout = 'boilerplate_base.html'

# send error emails to developers
send_mail_developer = True

# fellas' list
DEVELOPERS = (
    ('Alejandro Santamaria Arza', 'alexsmx@gmail.com'),
)

#facebook strings for development and production
fb_channel_file_prod ='//wishfan.com/'
fb_channel_file_dev='//localhost:8109/'
fb_appid_dev='341668639255311'
fb_secret_dev='b72d5386c6d5e1eda28db682a9313117'
fb_appid_prod='141940912616975'
fb_secret_prod='0747d18cead11ef69839d6f72a3c4161'
fb_channel=''
fb_appid=''