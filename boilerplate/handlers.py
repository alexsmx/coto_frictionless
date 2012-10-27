# -*- coding: utf-8 -*-

"""
    A real simple app for using webapp2 with auth and session.

    It just covers the basics. Creating a user, login, logout
    and a decorator for protecting certain handlers.

    Routes are setup in routes.py and added in main.py
"""
# standard library imports
import logging
import re
import json
import uuid
import urllib
import simplejson

# related third party imports
import webapp2
import httpagentparser
from webapp2_extras import security
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.i18n import gettext as _
from webapp2_extras.appengine.auth.models import Unique
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import images
from google.appengine.api import taskqueue
from google.appengine.api import urlfetch
from linkedin import linkedin

# local application/library specific imports
import config, models
import forms as forms

from lib import utils, captcha, twitter
from lib.basehandler import BaseHandler
from lib.basehandler import user_required
from lib import facebook


class RegisterBaseHandler(BaseHandler):
    """
    Base class for handlers with registration and login forms.
    """
    @webapp2.cached_property
    def form(self):
        if self.is_mobile:
            return forms.RegisterMobileForm(self)
        else:
            return forms.RegisterForm(self)


class SendEmailHandler(BaseHandler):
    """
    Core Handler for sending Emails
    Use with TaskQueue
    """
    def post(self):

        from google.appengine.api import mail, app_identity
        from google.appengine.api.datastore_errors import BadValueError
        from google.appengine.runtime import apiproxy_errors

        to = self.request.get("to")
        subject = self.request.get("subject")
        body = self.request.get("body")
        sender = self.request.get("sender")

        if sender != '' or not utils.is_email_valid(sender):
            if utils.is_email_valid(config.contact_sender):
                sender = config.contact_sender
            else:
                app_id = app_identity.get_application_id()
                sender = "%s <no-reply@%s.appspotmail.com>" % (app_id, app_id)

        try:
            logEmail = models.LogEmail(
                sender = sender,
                to = to,
                subject = subject,
                body = body,
                when = utils.get_date_time("datetimeProperty")
            )
            logEmail.put()
        except (apiproxy_errors.OverQuotaError, BadValueError):
            logging.error("Error saving Email Log in datastore")

        message = mail.EmailMessage()
        message.sender=sender
        message.to=to
        message.subject=subject
        message.html=body
        message.send()


class LoginHandler(BaseHandler):
    """
    Handler for authentication
    """

    def get(self):
        """ Returns a simple HTML form for login """

        if self.user:
            self.redirect_to('home')
        params = {}
        return self.render_template('boilerplate_login.html', **params)

    def post(self):
        """
        username: Get the username from POST dict
        password: Get the password from POST dict
        """

        if not self.form.validate():
            return self.get()
        username = self.form.username.data.lower()

        try:
            if utils.is_email_valid(username):
                user = models.User.get_by_email(username)
                if user:
                    auth_id = user.auth_ids[0]
                else:
                    raise InvalidAuthIdError
            else:
                auth_id = "own:%s" % username
                user = models.User.get_by_auth_id(auth_id)

            password = self.form.password.data.strip()
            remember_me = True if str(self.request.POST.get('remember_me')) == 'on' else False

            # Password to SHA512
            password = utils.hashing(password, config.salt)

            # Try to login user with password
            # Raises InvalidAuthIdError if user is not found
            # Raises InvalidPasswordError if provided password
            # doesn't match with specified user
            self.auth.get_user_by_password(
                auth_id, password, remember=remember_me)

            # if user account is not activated, logout and redirect to home
            if (user.activated == False):
                # logout
                self.auth.unset_session()

                # redirect to home with error message
                resend_email_uri = self.uri_for('resend-account-activation', user_id=user.get_id(),
                                                token=models.User.create_resend_token(user.get_id()))
                message = _('Your account has not yet been activated. Please check your email to activate it or') +\
                          ' <a href="'+resend_email_uri+'">' + _('click here') + '</a> ' + _('to resend the email.')
                self.add_message(message, 'error')
                return self.redirect_to('home')

            #check twitter association in session
            twitter_helper = twitter.TwitterAuth(self)
            twitter_association_data = twitter_helper.get_association_data()
            if twitter_association_data is not None:
                if models.SocialUser.check_unique(user.key, 'twitter', str(twitter_association_data['id'])):
                    social_user = models.SocialUser(
                        user = user.key,
                        provider = 'twitter',
                        uid = str(twitter_association_data['id']),
                        extra_data = twitter_association_data
                    )
                    social_user.put()

            #check facebook association
            fb_data = None
            try:
                fb_data = json.loads(self.session['facebook'])
            except:
                pass

            if fb_data is not None:
                if models.SocialUser.check_unique(user.key, 'facebook', str(fb_data['id'])):
                    social_user = models.SocialUser(
                        user = user.key,
                        provider = 'facebook',
                        uid = str(fb_data['id']),
                        extra_data = fb_data
                    )
                    social_user.put()

            #check linkedin association
            li_data = None
            try:
                li_data = json.loads(self.session['linkedin'])
            except:
                pass
            if li_data is not None:
                if models.SocialUser.check_unique(user.key, 'linkedin', str(li_data['id'])):
                    social_user = models.SocialUser(
                        user = user.key,
                        provider = 'linkedin',
                        uid = str(li_data['id']),
                        extra_data = li_data
                    )
                    social_user.put()

            #end linkedin

            logVisit = models.LogVisit(
                user=user.key,
                uastring=self.request.user_agent,
                ip=self.request.remote_addr,
                timestamp=utils.get_date_time()
            )
            logVisit.put()
            self.redirect_to('home')
        except (InvalidAuthIdError, InvalidPasswordError), e:
            # Returns error message to self.response.write in
            # the BaseHandler.dispatcher
            message = _("Your username or password is incorrect. "
                        "Please try again (make sure your caps lock is off)")
            self.add_message(message, 'error')
            return self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.LoginForm(self)


class SocialLoginHandler(BaseHandler):
    """
    Handler for Social authentication
    """

    def get(self, provider_name):
        provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']

        if not config.enable_federated_login:
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')

        redirect_params=''
        process_name=''
        if self.request.GET.get('process_name'):
            process_name=self.request.GET.get('process_name')


        if self.request.GET.get('img_tmp_id'):
            redirect_params='?img_tmp_id='  + self.request.GET.get('img_tmp_id') + '&step=4'
        
        if process_name!='':
                redirect_params=redirect_params + '&process_name=' + process_name

        callback_url = "%s/social_login/%s/complete%s" % (self.request.host_url, provider_name, redirect_params)

        if provider_name == "twitter":
            twitter_helper = twitter.TwitterAuth(self, redirect_uri=callback_url)
            self.redirect(twitter_helper.auth_url())

        elif provider_name == "facebook":
            self.session['linkedin'] = None
            perms = ['email', 'publish_stream', 'friends_birthday', 'user_birthday', 'friends_about_me','friends_likes','friends_checkins','friends_events','friends_interests']
            self.redirect(facebook.auth_url(config._FbApiKey, callback_url, perms))

        elif provider_name == 'linkedin':
            self.session['facebook'] = None
            link = linkedin.LinkedIn(config.linkedin_api, config.linkedin_secret, callback_url)
            if link.request_token():
                self.session['request_token']=link._request_token
                self.session['request_token_secret']=link._request_token_secret
                self.redirect(link.get_authorize_url())

        else:
            message = _('%s authentication is not yet implemented.' % provider_display_name)
            self.add_message(message, 'warning')
            self.redirect_to('edit-profile')


class CallbackSocialLoginHandler(BaseHandler):
    """
    updateTmpImageWithUser 
    """
    def updateTmpImageWithUser(self,user, tmp_id):
        temp_item = models.ItemEvent.query(models.ItemEvent.temp_id==tmp_id).get()
        temp_item.user=user.key
        temp_item.put()
    """
    Callback (Save Information) for Social Authentication
    """

    def get(self, provider_name):
        if not config.enable_federated_login:
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')
        if provider_name == "twitter":
            oauth_token = self.request.get('oauth_token')
            oauth_verifier = self.request.get('oauth_verifier')
            twitter_helper = twitter.TwitterAuth(self)
            user_data = twitter_helper.auth_complete(oauth_token,
                oauth_verifier)
            if self.user:
                # new association with twitter
                user_info = models.User.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'twitter', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user = user_info.key,
                        provider = 'twitter',
                        uid = str(user_data['id']),
                        extra_data = user_data
                    )
                    social_user.put()

                    message = _('Twitter association added.')
                    self.add_message(message, 'success')
                else:
                    message = _('This Twitter account is already in use.')
                    self.add_message(message, 'error')
                self.redirect_to('edit-profile')
            else:
                # login with twitter
                social_user = models.SocialUser.get_by_provider_and_uid('twitter',
                    str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    logVisit = models.LogVisit(
                        user = user.key,
                        uastring = self.request.user_agent,
                        ip = self.request.remote_addr,
                        timestamp = utils.get_date_time()
                    )
                    logVisit.put()
                    self.redirect_to('home')
                else:
                    # Social user does not exists. Need show login and registration forms
                    twitter_helper.save_association_data(user_data)
                    message = _('This Twitter account is not associated with any local account. '
                                'If you already have a %s Account, you have <a href="/login/">sign in here</a> '
                                'or <a href="/register/">create an account</a>.' % config.app_name)
                    self.add_message(message, 'warning')
                    self.redirect_to('login')

        #facebook association
        elif provider_name == "facebook":
            code = self.request.get('code')
            #If user not authorizes then the code does not exists, instead there is an answer in this form: 
            # YOUR_REDIRECT_URI?
            # error_reason=user_denied
            # &error=access_denied
            # &error_description=The+user+denied+your+request.
            # &state=YOUR_STATE_VALUE
            redirect_params=''
            img_tmp_id=''
            process_name=''
            if self.request.GET.get('process_name'):
                process_name=self.request.GET.get('process_name')

            if self.request.GET.get('img_tmp_id'):
                img_tmp_id=self.request.GET.get('img_tmp_id')
                redirect_params='?img_tmp_id='  + self.request.GET.get('img_tmp_id') + '&step=4'

            if process_name!='':
                redirect_params=redirect_params + '&process_name=' + process_name

            callback_url = "%s/social_login/%s/complete%s" % (self.request.host_url, provider_name, redirect_params)
            try:
                token = facebook.get_access_token_from_code(code, callback_url, config._FbApiKey, config._FbSecret)
            except Exception as e:
                logging.error("error getting facebook token: %s" % e)
                message = _('Failed to login with Facebook. Try another method. %s ' % config.app_name)
                self.add_message(message, 'warning')
                if img_tmp_id == '':
                    return self.redirect_to('home')
                else:
                    if process_name=='pagoparticipacion':
                        return self.redirect(self.uri_for('participate_in_event') + redirect_params + '&result=error_login')
                    else:
                        return self.redirect(self.uri_for('first-product') + redirect_params)
            #if we have a token, then we are going to check if we can have a user,
            #in anycase whenever we have an img_tmp_id and get a grip of a user, we are going to 
            #update the user keyproperty there, we also grab the token an token expiration for the rest of 
            #the use case
            access_token = token['access_token']
            token_expires= long(token['expires'])
            fb = facebook.GraphAPI(access_token)
            user_data = fb.get_object('me')
            profile_picture=fb.get_object('me/picture')
            logging.info(profile_picture['url'])
            #this is checking if you're already logged in , maybe with a registered user
            #cause if your are, then all you have to do is an association with that already 
            #registered user.
            if self.user:
                # new association with facebook
                user_info = models.User.get_by_id(long(self.user_id))
                if img_tmp_id !='':
                    if process_name!='pagoparticipacion':
                        self.updateTmpImageWithUser(user_info, img_tmp_id)
                if models.SocialUser.check_unique(user_info.key, 'facebook', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user = user_info.key,
                        provider = 'facebook',
                        uid = str(user_data['id']),
                        extra_data = user_data,
                        auth_token=access_token,
                        expires=token_expires,
                        profile_picture_url=profile_picture['url']
                    )
                    social_user.put()

                    message = _('Facebook association added!')
                    self.add_message(message,'success')
                else:
                    message = _('This Facebook account is already in use!')
                    self.add_message(message,'error')
                self.redirect_to('edit-profile')
            #if you are not already logged in, then it is going to try and see if there's an association 
            #in order to log you in using that association.
            else:
                # login with Facebook
                social_user = models.SocialUser.get_by_provider_and_uid('facebook',
                    str(user_data['id']))
                #here it is checking if there is association, if not, the regular path is to send you to 
                #register and login (IMHO: friction!)
                if social_user:
                    #we update token and expire
                    social_user.auth_token= access_token
                    social_user.expires= token_expires
                    social_user.put()
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    #if we have an image, we update user key
                    if img_tmp_id !='':
                        if process_name!='pagoparticipacion':
                            self.updateTmpImageWithUser(user, img_tmp_id)
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    logVisit = models.LogVisit(
                        user = user.key,
                        uastring = self.request.user_agent,
                        ip = self.request.remote_addr,
                        timestamp = utils.get_date_time()
                    )
                    logVisit.put()
                    logging.info('img_tmp_id OJO:%s' % img_tmp_id)
                    logging.info('process_name OJO:%s' % process_name)
                    if img_tmp_id !='':
                        if process_name=='pagoparticipacion':
                            strredirect= self.uri_for('pay_for_event') + redirect_params 
                            logging.info(' OJO1:%s' % strredirect)
                            return self.redirect(self.uri_for('pay_for_event') + redirect_params )
                        else:
                            logging.info(' OJO2:')
                            return self.redirect(self.uri_for('first-product') + redirect_params)
                    else:
                        logging.info(' OJO3:')
                        self.redirect_to('home')
                else:
                    # Social user does not exists. Need show login and registration forms
                    
                    #we are already writing data into a session,
                    self.session['facebook']=json.dumps(user_data)
                    # here is the friction we want to remove so we setup a False if, to jump this section
                    if False:
                        login_url = '%s/login/'  % self.request.host_url
                        signup_url = '%s/register/' %  self.request.host_url
                        message = _('The Facebook account isn\'t associated with any local account. If you already have a Google App Engine Boilerplate Account, you have <a href="%s">sign in here</a> or <a href="%s">Create an account</a>') % (login_url, signup_url)
                        self.add_message(message,'info')
                        logging.info(' OJO4:')
                        self.redirect_to('login')
                    # use facebook user info to create a user, validate, login, 
                    # create a social user and associate and go on with your life!
                    fb_username= user_data['username'].strip()
                    fb_name=user_data['name'].strip()
                    fb_last_name=user_data['last_name'].strip()
                    fb_email=user_data['email'].strip()
                    fb_password=utils.random_string()
                    try:
                        fb_country=user_data['hometown']['name'].strip()
                    except Exception as e: 
                        fb_country=''
                    # Password to SHA512
                    fb_password = utils.hashing(fb_password, config.salt)
                    # Passing password_raw=password so password will be hashed
                    # Returns a tuple, where first value is BOOL.
                    # If True ok, If False no new user is created
                    unique_properties = ['username', 'email']
                    auth_id = "fbn:%s" % fb_username
                    user = self.auth.store.user_model.create_user(
                        auth_id, unique_properties, password_raw=fb_password,
                        username=fb_username, name=fb_name, last_name=fb_last_name, email=fb_email,
                        ip=self.request.remote_addr, country=fb_country, activated=True
                    )
                    #if the first return value user[0] is false then there was a problem, send to register.
                    if not user[0]: #user is a tuple
                        if "username" in str(user[1]):
                            message = _('Sorry, The username %s is already registered.' % '<strong>{0:>s}</strong>'.format(fb_username) )
                        elif "email" in str(user[1]):
                            message = _('Sorry, The email %s is already registered.' % '<strong>{0:>s}</strong>'.format(fb_email) )
                        else:
                            message = _('Sorry, The user is already registered.')
                        self.add_message(message, 'error')
                        return self.redirect_to('register')
                    else:
                        #user registered correctly, login.
                        try:
                            user_info = models.User.get_by_email(fb_email)
                            #if we have temporal image we store it
                            if img_tmp_id !='':
                                if process_name!='pagoparticipacion':
                                    self.updateTmpImageWithUser(user_info, img_tmp_id)
                            db_user = self.auth.get_user_by_password(user[1].auth_ids[0], fb_password)
                            fb_data = json.loads(self.session['facebook'])
                            if fb_data is not None:
                                if models.SocialUser.check_unique(user_info.key, 'facebook', str(fb_data['id'])):
                                    social_user = models.SocialUser(
                                        user = user_info.key,
                                        provider = 'facebook',
                                        uid = str(fb_data['id']),
                                        extra_data = fb_data,
                                        auth_token=access_token,
                                        expires=token_expires,
                                        profile_picture_url=profile_picture['url']
                                    )
                                    social_user.put()
                            message = _('Welcome %s, you are now logged in.' % '<strong>{0:>s}</strong>'.format(fb_username) )
                            self.add_message(message, 'success')
                            if img_tmp_id == '':
                                logging.info(' OJO6:')
                                return self.redirect_to('home')
                            else:
                                if process_name=='pagoparticipacion':
                                    logging.info(' OJO7:')
                                    return self.redirect(self.uri_for('pay_for_event') + redirect_params)
                                else:
                                    logging.info(' OJO8:')
                                    return self.redirect(self.uri_for('first-product') + redirect_params)
                        except (AttributeError, KeyError), e:
                            logging.error('Unexpected error creating the user %s: %s' % (fb_username, e ))
                            message = _('Unexpected error creating the user %s' % fb_username )
                            self.add_message(message, 'error')
                            logging.info(' OJO9:')
                            return self.redirect_to('home')

            #end facebook
         # association with linkedin
        elif provider_name == "linkedin":
            callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)
            link = linkedin.LinkedIn(config.linkedin_api, config.linkedin_secret, callback_url)
            request_token = self.session['request_token']
            request_token_secret= self.session['request_token_secret']
            link._request_token = request_token
            link._request_token_secret = request_token_secret
            verifier = self.request.get('oauth_verifier')
            #~ print 'test'
            #~ print 'request_token= %s ; request_token_secret= %s ;verifier = %s ' % (request_token, request_token_secret, verifier)
            link.access_token(verifier=verifier)
            u_data = link.get_profile()
            user_key = re.search(r'key=(\d+)', u_data.private_url).group(1)
            user_data={'first_name':u_data.first_name, 'last_name':u_data.last_name ,'id':user_key}
            self.session['linkedin'] = json.dumps(user_data)

            if self.user:
                # new association with linkedin
                user_info = models.User.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'linkedin', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user = user_info.key,
                        provider = 'linkedin',
                        uid = str(user_data['id']),
                        extra_data = user_data
                    )
                    social_user.put()

                    message = _('Linkedin association added!')
                    self.add_message(message,'success')
                else:
                    message = _('This Linkedin account is already in use!')
                    self.add_message(message,'error')
                self.redirect_to('edit-profile')
            else:
                # login with Linkedin
                social_user = models.SocialUser.get_by_provider_and_uid('linkedin',
                    str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    logVisit = models.LogVisit(
                        user = user.key,
                        uastring = self.request.user_agent,
                        ip = self.request.remote_addr,
                        timestamp = utils.get_date_time()
                    )
                    logVisit.put()
                    self.redirect_to('home')
                else:
                    # Social user does not exists. Need show login and registration forms
                    self.session['linkedin'] = json.dumps(user_data)
                    login_url = '%s/login/'  % self.request.host_url
                    signup_url = '%s/register/' %  self.request.host_url
                    message = _('The Linkedin account isn\'t associated with any local account. If you already have a Google App Engine Boilerplate Account, you have <a href="%s">sign in here</a> or <a href="%s">Create an account</a>') % (login_url, signup_url)
                    self.add_message(message,'info')
                    self.redirect_to('login')

            #end linkedin


            # Debug Callback information provided
#            for k,v in user_data.items():
#                print(k +":"+  v )
        # google, myopenid, yahoo OpenID Providers
        elif provider_name in models.SocialUser.open_id_providers():
            provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']
            # get info passed from OpenId Provider
            from google.appengine.api import users
            current_user = users.get_current_user()
            if current_user:
                if current_user.federated_identity():
                    uid = current_user.federated_identity()
                else:
                    uid = current_user.user_id()
                email = current_user.email()
            else:
                message = _('No user authentication information received from %s. '
                            'Please ensure you are logging in from an authorized OpenID Provider (OP).'
                            % provider_display_name)
                self.add_message(message, 'error')
                return self.redirect_to('login')
            if self.user:
                # add social account to user
                user_info = models.User.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, provider_name, uid):
                    social_user = models.SocialUser(
                        user = user_info.key,
                        provider = provider_name,
                        uid = uid
                    )
                    social_user.put()

                    message = _('%s association successfully added.' % provider_display_name)
                    self.add_message(message, 'success')
                else:
                    message = _('This %s account is already in use.' % provider_display_name)
                    self.add_message(message, 'error')
                self.redirect_to('edit-profile')
            else:
                # login with OpenId Provider
                social_user = models.SocialUser.get_by_provider_and_uid(provider_name, uid)
                if social_user:
                    # Social user found. Authenticate the user
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    logVisit = models.LogVisit(
                        user = user.key,
                        uastring = self.request.user_agent,
                        ip = self.request.remote_addr,
                        timestamp = utils.get_date_time()
                    )
                    logVisit.put()
                    self.redirect_to('home')
                else:
                    # Social user does not exist yet so create it with the federated identity provided (uid)
                    # and create prerequisite user and log the user account in
                    if models.SocialUser.check_unique_uid(provider_name, uid):
                        # create user
                        # Returns a tuple, where first value is BOOL.
                        # If True ok, If False no new user is created
                        # Assume provider has already verified email address
                        # if email is provided so set activated to True
                        auth_id = "%s:%s" % (provider_name, uid)
                        if email:
                            unique_properties = ['email']
                            user_info = self.auth.store.user_model.create_user(
                                auth_id, unique_properties, email=email,
                                activated=True
                            )
                        else:
                            user_info = self.auth.store.user_model.create_user(
                                auth_id, activated=True
                            )
                        if not user_info[0]: #user is a tuple
                            message = _('The account %s is already in use.' % provider_display_name)
                            self.add_message(message, 'error')
                            return self.redirect_to('register')

                        user = user_info[1]

                        # create social user and associate with user
                        social_user = models.SocialUser(
                            user = user.key,
                            provider = provider_name,
                            uid = uid
                        )
                        social_user.put()
                        # authenticate user
                        self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                        logVisit = models.LogVisit(
                            user = user.key,
                            uastring = self.request.user_agent,
                            ip = self.request.remote_addr,
                            timestamp = utils.get_date_time()
                        )
                        logVisit.put()
                        self.redirect_to('home')

                        message = _('%s association successfully added.' % provider_display_name)
                        self.add_message(message, 'success')
                        self.redirect_to('home')
                    else:
                        message = _('This %s account is already in use.' % provider_display_name)
                        self.add_message(message, 'error')
                    self.redirect_to('login')
        else:
            message = _('This authentication method is not yet implemented.')
            self.add_message(message, 'warning')
            self.redirect_to('login')


class DeleteSocialProviderHandler(BaseHandler):
    """
    Delete Social association with an account
    """

    @user_required
    def get(self, provider_name):
        if self.user:
            user_info = models.User.get_by_id(long(self.user_id))
            social_user = models.SocialUser.get_by_user_and_provider(user_info.key, provider_name)
            if social_user:
                social_user.key.delete()
                message = _('%s successfully disassociated.' % provider_name)
                self.add_message(message, 'success')
            else:
                message = _('Social account on %s not found for this user.' % provider_name)
                self.add_message(message, 'error')
        self.redirect_to('edit-profile')


class LogoutHandler(BaseHandler):
    """
    Destroy user session and redirect to login
    """

    def get(self):
        if self.user:
            message = _("You've signed out successfully. Warning: Please clear all cookies and logout "
                        "of OpenId providers too if you logged in on a public computer.")
            self.add_message(message, 'info')

        self.auth.unset_session()
        # User is logged out, let's try redirecting to login page
        try:
            self.redirect(self.auth_config['home_url'])
        except (AttributeError, KeyError), e:
            logging.error("Error logging out: %s" % e)
            message = _("User is logged out, but there was an error on the redirection.")
            self.add_message(message, 'error')
            return self.redirect_to('home')


class RegisterHandler(RegisterBaseHandler):
    """
    Handler for Sign Up Users
    """

    def get(self):
        """ Returns a simple HTML form for create a new user """

        if self.user:
            self.redirect_to('home')
        params = {}
        return self.render_template('boilerplate_register.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        password = self.form.password.data.strip()
        country = self.form.country.data

        # Password to SHA512
        password = utils.hashing(password, config.salt)

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            ip=self.request.remote_addr, country=country
        )

        if not user[0]: #user is a tuple
            if "username" in str(user[1]):
                message = _('Sorry, The username %s is already registered.' % '<strong>{0:>s}</strong>'.format(username) )
            elif "email" in str(user[1]):
                message = _('Sorry, The email %s is already registered.' % '<strong>{0:>s}</strong>'.format(email) )
            else:
                message = _('Sorry, The user is already registered.')
            self.add_message(message, 'error')
            return self.redirect_to('register')
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                user_info = models.User.get_by_email(email)
                if (user_info.activated == False):
                    # send email
                    subject =  _("%s Account Verification" % config.app_name)
                    confirmation_url = self.uri_for("account-activation",
                        user_id=user_info.get_id(),
                        token = models.User.create_auth_token(user_info.get_id()),
                        _full = True)

                    # load email's template
                    template_val = {
                        "app_name": config.app_name,
                        "username": username,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url = email_url, params={
                        'to': str(email),
                        'subject' : subject,
                        'body' : body,
                        })

                    message = _('You were successfully registered. '
                                'Please check your email to activate your account.')
                    self.add_message(message, 'success')
                    return self.redirect_to('home')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(user[1].auth_ids[0], password)
                # Check twitter association in session
                twitter_helper = twitter.TwitterAuth(self)
                twitter_association_data = twitter_helper.get_association_data()
                if twitter_association_data is not None:
                    if models.SocialUser.check_unique(user[1].key, 'twitter', str(twitter_association_data['id'])):
                        social_user = models.SocialUser(
                            user = user[1].key,
                            provider = 'twitter',
                            uid = str(twitter_association_data['id']),
                            extra_data = twitter_association_data
                        )
                        social_user.put()

                #check facebook association
                fb_data = json.loads(self.session['facebook'])

                if fb_data is not None:
                    if models.SocialUser.check_unique(user.key, 'facebook', str(fb_data['id'])):
                        social_user = models.SocialUser(
                            user = user.key,
                            provider = 'facebook',
                            uid = str(fb_data['id']),
                            extra_data = fb_data
                        )
                        social_user.put()
                #check linkedin association
                li_data = json.loads(self.session['linkedin'])
                if li_data is not None:
                    if models.SocialUser.check_unique(user.key, 'linkedin', str(li_data['id'])):
                        social_user = models.SocialUser(
                            user = user.key,
                            provider = 'linkedin',
                            uid = str(li_data['id']),
                            extra_data = li_data
                        )
                        social_user.put()


                message = _('Welcome %s, you are now logged in.' % '<strong>{0:>s}</strong>'.format(username) )
                self.add_message(message, 'success')
                return self.redirect_to('home')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _('Unexpected error creating the user %s' % username )
                self.add_message(message, 'error')
                return self.redirect_to('home')


class AccountActivationHandler(BaseHandler):
    """
    Handler for account activation
    """

    def get(self, user_id, token):
        try:
            if not models.User.validate_auth_token(user_id, token):
                message = _('The link is invalid.')
                self.add_message(message, 'error')
                return self.redirect_to('home')

            user = models.User.get_by_id(long(user_id))
            # activate the user's account
            user.activated = True
            user.put()

            # Login User
            self.auth.get_user_by_token(int(user_id), token)

            # Delete token
            models.User.delete_auth_token(user_id, token)

            message = _('Congratulations, Your account %s has been successfully activated.'
                        % '<strong>{0:>s}</strong>'.format(user.username) )
            self.add_message(message, 'success')
            self.redirect_to('home')

        except (AttributeError, KeyError, InvalidAuthIdError, NameError), e:
            logging.error("Error activating an account: %s" % e)
            message = _('Sorry, Some error occurred.')
            self.add_message(message, 'error')
            return self.redirect_to('home')


class ResendActivationEmailHandler(BaseHandler):
    """
    Handler to resend activation email
    """

    def get(self, user_id, token):
        try:
            if not models.User.validate_resend_token(user_id, token):
                message = _('The link is invalid.')
                self.add_message(message, 'error')
                return self.redirect_to('home')

            user = models.User.get_by_id(long(user_id))
            email = user.email

            if (user.activated == False):
                # send email
                subject = _("%s Account Verification" % config.app_name)
                confirmation_url = self.uri_for("account-activation",
                    user_id = user.get_id(),
                    token = models.User.create_auth_token(user.get_id()),
                    _full = True)

                # load email's template
                template_val = {
                    "app_name": config.app_name,
                    "username": user.username,
                    "confirmation_url": confirmation_url,
                    "support_url": self.uri_for("contact", _full=True)
                }
                body_path = "emails/account_activation.txt"
                body = self.jinja2.render_template(body_path, **template_val)

                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url = email_url, params={
                    'to': str(email),
                    'subject' : subject,
                    'body' : body,
                    })

                models.User.delete_resend_token(user_id, token)

                message = _('The verification email has been resent to %s. '
                            'Please check your email to activate your account.' % email)
                self.add_message(message, 'success')
                return self.redirect_to('home')
            else:
                message = _('Your account has been activated. Please <a href="/login/">sign in</a> to your account.')
                self.add_message(message, 'warning')
                return self.redirect_to('home')

        except (KeyError, AttributeError), e:
            logging.error("Error resending activation email: %s" % e)
            message = _('Sorry, Some error occurred.')
            self.add_message(message, 'error')
            return self.redirect_to('home')


class ContactHandler(BaseHandler):
    """
    Handler for Contact Form
    """

    def get(self):
        """ Returns a simple HTML for contact form """

        if self.user:
            user_info = models.User.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params = {
            "exception" : self.request.get('exception')
            }

        return self.render_template('boilerplate_contact.html', **params)

    def post(self):
        """ validate contact form """

        if not self.form.validate():
            return self.get()
        remoteip  = self.request.remote_addr
        user_agent  = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()

        try:
            # parsing user_agent and getting which os key to use
            # windows uses 'os' while other os use 'flavor'
            ua = httpagentparser.detect(user_agent)
            os = ua.has_key('flavor') and 'flavor' or 'os'

            template_val = {
                "name": name,
                "email": email,
                "browser": str(ua['browser']['name']),
                "browser_version": str(ua['browser']['version']),
                "operating_system": str(ua[os]['name']) + " " +
                                    str(ua[os]['version']),
                "ip": remoteip,
                "message": message
            }
        except Exception as e:
            logging.error("error getting user agent info: %s" % e)

        try:
            subject = _("Contact")
            # exceptions for error pages that redirect to contact
            if exception != "":
                subject = subject + " (Exception error: %s)" % exception

            body_path = "emails/contact.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url = email_url, params={
                'to': config.contact_recipient,
                'subject' : subject,
                'body' : body,
                'sender' : config.contact_sender,
                })

            message = _('Your message was sent successfully.')
            self.add_message(message, 'success')
            return self.redirect_to('contact')

        except (AttributeError, KeyError), e:
            logging.error('Error sending contact form: %s' % e)
            message = _('Error sending the message. Please try again later.')
            self.add_message(message, 'error')
            return self.redirect_to('contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)


class EditProfileHandler(BaseHandler):
    """
    Handler for Edit User Profile
    """

    @user_required
    def get(self):
        """ Returns a simple HTML form for edit profile """

        params = {}
        if self.user:
            user_info = models.User.get_by_id(long(self.user_id))
            self.form.username.data = user_info.username
            self.form.name.data = user_info.name
            self.form.last_name.data = user_info.last_name
            self.form.country.data = user_info.country
            providers_info = user_info.get_social_providers_info()
            params['used_providers'] = providers_info['used']
            params['unused_providers'] = providers_info['unused']
            params['country'] = user_info.country

        return self.render_template('boilerplate_edit_profile.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        country = self.form.country.data

        try:
            user_info = models.User.get_by_id(long(self.user_id))

            try:
                message=''
                # update username if it has changed and it isn't already taken
                if username != user_info.username:
                    user_info.unique_properties = ['username','email']
                    uniques = [
                               'User.username:%s' % username,
                               'User.auth_id:own:%s' % username,
                               ]
                    # Create the unique username and auth_id.
                    success, existing = Unique.create_multi(uniques)
                    if success:
                        # free old uniques
                        Unique.delete_multi(['User.username:%s' % user_info.username, 'User.auth_id:own:%s' % user_info.username])
                        # The unique values were created, so we can save the user.
                        user_info.username=username
                        user_info.auth_ids[0]='own:%s' % username
                        message+= _('Your new username is %s' % '<strong>{0:>s}</strong>'.format(username) )

                    else:
                        message+= _('The username %s is already taken. Please choose another.'
                                % '<strong>{0:>s}</strong>'.format(username) )
                        # At least one of the values is not unique.
                        self.add_message(message, 'error')
                        return self.get()
                user_info.name=name
                user_info.last_name=last_name
                user_info.country=country
                user_info.put()
                message+= " " + _('Thanks, your settings have been saved.')
                self.add_message(message, 'success')
                return self.get()

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating profile: ' + e)
                message = _('Unable to update profile. Please try again later.')
                self.add_message(message, 'error')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _('Sorry you are not logged in.')
            self.add_message(login_error_message, 'error')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditProfileForm(self)


class EditPasswordHandler(BaseHandler):
    """
    Handler for Edit User Password
    """

    @user_required
    def get(self):
        """ Returns a simple HTML form for editing password """

        params = {}
        return self.render_template('boilerplate_edit_password.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()
        current_password = self.form.current_password.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = models.User.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username

            # Password to SHA512
            current_password = utils.hashing(current_password, config.salt)
            try:
                user = models.User.get_by_auth_password(auth_id, current_password)
                # Password to SHA512
                password = utils.hashing(password, config.salt)
                user.password = security.generate_password_hash(password, length=12)
                user.put()

                # send email
                subject = config.app_name + " Account Password Changed"

                # load email's template
                template_val = {
                    "app_name": config.app_name,
                    "first_name": user.name,
                    "username": user.username,
                    "email": user.email,
                    "reset_password_url": self.uri_for("password-reset", _full=True)
                }
                email_body_path = "emails/password_changed.txt"
                email_body = self.jinja2.render_template(email_body_path, **template_val)
                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url = email_url, params={
                    'to': user.email,
                    'subject' : subject,
                    'body' : email_body,
                    'sender' : config.contact_sender,
                    })

                #Login User
                self.auth.get_user_by_password(user.auth_ids[0], password)
                self.add_message(_('Password changed successfully.'), 'success')
                return self.redirect_to('edit-profile')
            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _("Incorrect password! Please enter your current password to change your account settings.")
                self.add_message(message, 'error')
                return self.redirect_to('edit-password')
        except (AttributeError,TypeError), e:
            login_error_message = _('Sorry you are not logged in.')
            self.add_message(login_error_message, 'error')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        if self.is_mobile:
            return forms.EditPasswordMobileForm(self)
        else:
            return forms.EditPasswordForm(self)


class EditEmailHandler(BaseHandler):
    """
    Handler for Edit User's Email
    """

    @user_required
    def get(self):
        """ Returns a simple HTML form for edit email """

        params = {}
        if self.user:
            user_info = models.User.get_by_id(long(self.user_id))
            params['current_email'] = user_info.email

        return self.render_template('boilerplate_edit_email.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()
        new_email = self.form.new_email.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = models.User.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            # Password to SHA512
            password = utils.hashing(password, config.salt)

            try:
                # authenticate user by its password
                user = models.User.get_by_auth_password(auth_id, password)

                # if the user change his/her email address
                if new_email != user.email:

                    # check whether the new email has been used by another user
                    aUser = models.User.get_by_email(new_email)
                    if aUser is not None:
                        message = _("The email %s is already registered." % new_email)
                        self.add_message(message, 'error')
                        return self.redirect_to("edit-email")

                    # send email
                    subject = _("%s Email Changed Notification" % config.app_name)
                    user_token = models.User.create_auth_token(self.user_id)
                    confirmation_url = self.uri_for("email-changed-check",
                        user_id = user_info.get_id(),
                        encoded_email = utils.encode(new_email),
                        token = user_token,
                        _full = True)

                    # load email's template
                    template_val = {
                        "app_name": config.app_name,
                        "first_name": user.name,
                        "username": user.username,
                        "new_email": new_email,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True)
                    }

                    old_body_path = "emails/email_changed_notification_old.txt"
                    old_body = self.jinja2.render_template(old_body_path, **template_val)

                    new_body_path = "emails/email_changed_notification_new.txt"
                    new_body = self.jinja2.render_template(new_body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url = email_url, params={
                        'to': user.email,
                        'subject' : subject,
                        'body' : old_body,
                        })
                    taskqueue.add(url = email_url, params={
                        'to': new_email,
                        'subject' : subject,
                        'body' : new_body,
                        })

                    # display successful message
                    msg = _("Please check your new email for confirmation. Your email will be updated after confirmation.")
                    self.add_message(msg, 'success')
                    return self.redirect_to('edit-profile')

                else:
                    self.add_message(_("You didn't change your email."), "warning")
                    return self.redirect_to("edit-email")


            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _("Incorrect password! Please enter your current password to change your account settings.")
                self.add_message(message, 'error')
                return self.redirect_to('edit-email')

        except (AttributeError,TypeError), e:
            login_error_message = _('Sorry you are not logged in.')
            self.add_message(login_error_message,'error')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditEmailForm(self)


class PasswordResetHandler(BaseHandler):
    """
    Password Reset Handler with Captcha
    """

    reCaptcha_public_key = config.captcha_public_key
    reCaptcha_private_key = config.captcha_private_key

    def get(self):
        chtml = captcha.displayhtml(
            public_key = self.reCaptcha_public_key,
            use_ssl = False,
            error = None)
        if self.reCaptcha_public_key == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
           self.reCaptcha_private_key == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
            chtml = '<div class="alert alert-error"><strong>Error</strong>: You have to <a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                    'for API keys</a> in order to use reCAPTCHA.</div>' \
                    '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                    '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
        params = {
            'captchahtml': chtml,
            }
        return self.render_template('boilerplate_password_reset.html', **params)

    def post(self):
        # check captcha
        challenge = self.request.POST.get('recaptcha_challenge_field')
        response  = self.request.POST.get('recaptcha_response_field')
        remoteip  = self.request.remote_addr

        cResponse = captcha.submit(
            challenge,
            response,
            self.reCaptcha_private_key,
            remoteip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _('Wrong image verification code. Please try again.')
            self.add_message(_message, 'error')
            return self.redirect_to('password-reset')
            #check if we got an email or username
        email_or_username = str(self.request.POST.get('email_or_username')).lower().strip()
        if utils.is_email_valid(email_or_username):
            user = models.User.get_by_email(email_or_username)
            _message = _("If the e-mail address you entered") + " (<strong>%s</strong>) " % email_or_username
        else:
            auth_id = "own:%s" % email_or_username
            user = models.User.get_by_auth_id(auth_id)
            _message = _("If the username you entered") + " (<strong>%s</strong>) " % email_or_username

        _message = _message + _("is associated with an account in our records, you will receive "
                                "an e-mail from us with instructions for resetting your password. "
                                "<br>If you don't receive instructions within a minute or two, "
                                "check your email's spam and junk filters, or ") +\
                   '<a href="' + self.uri_for('contact') + '">' + _('contact us') + '</a> ' +  _("for further assistance.")

        if user is not None:
            user_id = user.get_id()
            token = models.User.create_auth_token(user_id)
            email_url = self.uri_for('taskqueue-send-email')
            reset_url = self.uri_for('password-reset-check', user_id=user_id, token=token, _full=True)
            subject = _("%s Password Assistance" % config.app_name)

            # load email's template
            template_val = {
                "username": user.username,
                "email": user.email,
                "reset_password_url": reset_url,
                "support_url": self.uri_for("contact", _full=True),
                "app_name": config.app_name,
            }

            body_path = "emails/reset_password.txt"
            body = self.jinja2.render_template(body_path, **template_val)
            taskqueue.add(url = email_url, params={
                'to': user.email,
                'subject' : subject,
                'body' : body,
                'sender' : config.contact_sender,
                })
            self.add_message(_message, 'success')
            return self.redirect_to('login')
        self.add_message(_message, 'warning')
        return self.redirect_to('password-reset')


class PasswordResetCompleteHandler(BaseHandler):
    """
    Handler to process the link of reset password that received the user
    """

    def get(self, user_id, token):
        verify = models.User.get_by_auth_token(int(user_id), token)
        params = {}
        if verify[0] is None:
            message = _('The URL you tried to use is either incorrect or no longer valid. '
                        'Enter your details again below to get a new one.')
            self.add_message(message, 'warning')
            return self.redirect_to('password-reset')

        else:
            return self.render_template('boilerplate_password_reset_complete.html', **params)

    def post(self, user_id, token):
        verify = models.User.get_by_auth_token(int(user_id), token)
        user = verify[0]
        password = self.form.password.data.strip()
        if user and self.form.validate():
            # Password to SHA512
            password = utils.hashing(password, config.salt)

            user.password = security.generate_password_hash(password, length=12)
            user.put()
            # Delete token
            models.User.delete_auth_token(int(user_id), token)
            # Login User
            self.auth.get_user_by_password(user.auth_ids[0], password)
            self.add_message(_('Password changed successfully.'), 'success')
            return self.redirect_to('home')

        else:
            self.add_message(_('The two passwords must match.'), 'error')
            return self.redirect_to('password-reset-check', user_id=user_id, token=token)

    @webapp2.cached_property
    def form(self):
        if self.is_mobile:
            return forms.PasswordResetCompleteMobileForm(self)
        else:
            return forms.PasswordResetCompleteForm(self)


class EmailChangedCompleteHandler(BaseHandler):
    """
    Handler for completed email change
    Will be called when the user click confirmation link from email
    """

    def get(self, user_id, encoded_email, token):
        verify = models.User.get_by_auth_token(int(user_id), token)
        email = utils.decode(encoded_email)
        if verify[0] is None:
            message = _('The URL you tried to use is either incorrect or no longer valid.')
            self.add_message(message, 'warning')
            self.redirect_to('home')

        else:
            # save new email
            user = verify[0]
            user.email = email
            user.put()
            # delete token
            models.User.delete_auth_token(int(user_id), token)
            # add successful message and redirect
            message = _('Your email has been successfully updated.')
            self.add_message(message, 'success')
            self.redirect_to('edit-profile')


class HomeRequestHandler(RegisterBaseHandler):
    """
    Handler to show the home page
    """

    def get(self):
        """ Returns a simple HTML form for home """
        logging.info('Existe usuario?: %s' % self.user)
        if self.user:
            params = {}
            params={}
            user_info = models.User.get_by_id(long(self.user_id))
            productos=models.ItemEvent.query(models.ItemEvent.user==user_info.key, models.ItemEvent.visible==True)
            payload=dict(productos=productos)
            params=payload
            return self.render_template('boilerplate_private_products.html', **params)
        else:
            params = {}
            return self.render_template('boilerplate_home.html', **params)    
        


class FirstProductHandler(RegisterBaseHandler):
    def get(self):
        tipo = self.request.GET.get('tipo')
        img_tmp_id=''
        paso=''
        tmp_producto_id = uuid.uuid1()
        params={}
        params['tipo']=tipo
        if self.request.GET.get('step'):
            paso=self.request.GET.get('step')
            params['paso']=paso

        if self.request.GET.get('img_tmp_id'):
            img_tmp_id=self.request.GET.get('img_tmp_id')
            params['img_tmp_id']=img_tmp_id
            tmp_producto_id=img_tmp_id
            params['isrevisit']=1
            saved_item= models.ItemEvent.query(models.ItemEvent.temp_id==img_tmp_id).get()
            params['saved_item']=saved_item

        params['tmp_producto_id']=tmp_producto_id
        upload_url = blobstore.create_upload_url('/upload/')
        params["upload_url"]= upload_url
        return self.render_template('boilerplate_first_product.html', **params)

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self):
        upload_files = self.get_uploads('file')  # 'file' is file upload field in the form
        blob_info = upload_files[0]
        blob_key=blob_info.key()
        logging.info("Blob resource %s" % blob_key)
        #img= images.Image(blob_key)
        serving_url= images.get_serving_url(blob_key)
        logging.info("Serving url %s" % serving_url)
        self.response.out.write(serving_url)
        #self.redirect('/serve/%s' % blob_info.key())

class getUploadURLHandler(BaseHandler):
    def get(self):
        upload_url = blobstore.create_upload_url('/upload/')
        self.response.out.write(upload_url)

class getGuid(BaseHandler):
    def get(self):
        str_guid= uuid.uuid1()
        self.response.out.write(str_guid)



class testNDBModelRequestHandler(BaseHandler): 
    def post(self):
        user_info = models.User.get_by_id(long(self.user_id))
        prueba= models.Test(user=user_info.key, field1="prueba", field2="preuba", field3="pruba")
        prueba.put()
        self.redirect_to('home')

    @user_required   
    def get(self):
        if self.user:
            user_info = models.User.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params = {
            "exception" : self.request.get('exception')
            }

        return self.render_template('test.html', **params)

    @webapp2.cached_property
    def form(self):
        return forms.TestForm(self)

class PostEvent(BaseHandler):
    def post(self):
        suser= self.request.get("user")
        stemp_id=self.request.get("temp_id")
        stipo_evento=self.request.get("tipo_evento")
        sfecha_evento=self.request.get("fecha_evento")
        stitulo_evento = self.request.get("titulo_evento")
        sdescripcion= self.request.get("descripcion")
        smeta_evento=self.request.get("meta_evento")
        sformato_contribucion_evento=self.request.get("formato_contribucion_evento")
        smonto_contribucion_evento=self.request.get("monto_contribucion_evento")
        simage_url=self.request.get("image_url")
        logging.info('stemp_id=%s' % stemp_id)
        saved_event=models.ItemEvent.query(models.ItemEvent.temp_id==stemp_id).get()
        if saved_event:
            logging.info('saved_event exists')
            if suser!='':
                user_info = models.User.get_by_id(long(self.user_id))
                saved_event.user=user_info.key
            saved_event.tipo_evento=stipo_evento
            saved_event.fecha_evento=sfecha_evento
            saved_event.titulo_evento=stitulo_evento
            saved_event.descripcion=sdescripcion
            saved_event.meta_evento=smeta_evento
            saved_event.formato_contribucion_evento=sformato_contribucion_evento
            saved_event.monto_contribucion_evento=smonto_contribucion_evento
            saved_event.image_url=simage_url
            try:
                saved_event.put()
            except Exception as e:
                self.response.out.write('Error al registrar el evento') 
        else:
            logging.info('saved_event dont exists')
            if suser!='':
                user_info = models.User.get_by_id(long(self.user_id))
                nuevoEvento=models.ItemEvent(user=user_info.key, temp_id=stemp_id, tipo_evento=stipo_evento, fecha_evento=sfecha_evento, 
                    titulo_evento=stitulo_evento, descripcion_evento=sdescripcion, meta_evento=smeta_evento, 
                    formato_contribucion_evento=sformato_contribucion_evento, monto_contribucion_evento=smonto_contribucion_evento,
                    image_url=simage_url
                    )
            else:
                nuevoEvento=models.ItemEvent(temp_id=stemp_id, tipo_evento=stipo_evento, fecha_evento=sfecha_evento, 
                    titulo_evento=stitulo_evento, descripcion_evento=sdescripcion, meta_evento=smeta_evento, 
                    formato_contribucion_evento=sformato_contribucion_evento, monto_contribucion_evento=smonto_contribucion_evento,
                    image_url=simage_url
                    )
            try:
                nuevoEvento.put()
            except Exception as e:
                self.response.out.write('Error al registrar el evento') 
                return

        self.response.out.write('Evento registrado con éxito.')

class DeleteEvent(BaseHandler):
    @user_required
    def post(self):
        sevent_id= self.request.POST.get("event_id")
        if sevent_id!="":
            event_to_delete=models.ItemEvent.get_by_id(long(sevent_id))
            if event_to_delete:
                event_to_delete.visible=False
                event_to_delete.put()
                self.response.out.write('true')
            else:
                self.response.out.write('false')
        else:
            self.response.out.write('false')

class ParticipateHandler(RegisterBaseHandler):
    def get(self):
        sevent_temp_id=self.request.GET.get("temp_id")
        #shash_event= self.request.GET.get("h")
        #sevent_hash_check=utils.hashing(sevent_id, config.salt)
        if sevent_temp_id and sevent_temp_id!='' :
            event_to_show=models.ItemEvent.query(models.ItemEvent.temp_id==sevent_temp_id).get()
            if event_to_show:
                params={}
                params['producto']=event_to_show
                params['tmp_producto_id']=sevent_temp_id
                return self.render_template('boilerplate_participate_in_event.html', **params)
            else:
                return self.redirect_to('home')    
        else:
            return self.redirect_to('home')

class PaymentHandler(BaseHandler):
    @user_required
    def get(self):
        sevent_temp_id=self.request.GET.get("img_tmp_id")
        if sevent_temp_id and sevent_temp_id!='' :
            event_to_show=models.ItemEvent.query(models.ItemEvent.temp_id==sevent_temp_id).get()
            if event_to_show:
                params={}
                params['producto']=event_to_show
                return self.render_template('boilerplate_pay_event.html', **params)
            else:
                return self.redirect_to('home')    
        else:
            return self.redirect_to('home')


    """
    this will exclusively recive an proccess the payment order
    storing values to reference the payment
    updating the event with amount and participant 
    and saving info about a users contribution history linked to the payment
    reference which can be used to watch for past contributions
    """
    @user_required
    def post(self):
        surl =  "http://banwire.com/api.pago_pro"
        #surl =  "http://posttestserver.com/post.php"
        #we have to collect the necessary info from the client
        #upon which we will contruct the payment request to send to banwire.
        snombre=''
        spaterno=''
        smaterno=''
        stelefono=''
        sid_tarjeta=''
        snum_tarjeta=''
        snum_ccv=''
        svencimiento=''
        scalle=''
        snum_ext=''
        snum_int=''
        scodigo_postal=''
        sciudad=''
        smunicipio=''
        scolonia=''
        stipo_pago=''
        smonto=''
        semail=''

        snombre=self.request.POST.get('nombre')
        spaterno=self.request.POST.get('paterno')
        smaterno=self.request.POST.get('materno')
        stelefono=self.request.POST.get('telefono')
        sid_tarjeta=self.request.POST.get('id_tarjeta')
        snum_tarjeta=self.request.POST.get('numero_tarjeta')
        snum_ccv=self.request.POST.get('numero_ccv')
        svencimiento=self.request.POST.get('vencimiento')
        scalle=self.request.POST.get('calle')
        snum_ext=self.request.POST.get('num_ext')
        snum_int=self.request.POST.get('num_int')
        scolonia=self.request.POST.get('colonia')
        smunicipio=self.request.POST.get('municipio') 
        scodigo_postal=self.request.POST.get('codigo_postal')
        sciudad=self.request.POST.get('ciudad')
        stipo_pago=self.request.POST.get('tipo_pago')
        simg_tmp_id=self.request.POST.get('tc_img_tmp_id')
        smonto=self.request.POST.get('montotc')
        semail=self.request.POST.get('emailtc')
        snombre_completo=snombre + ' ' + spaterno + ' ' + smaterno
        sdireccion_completa=scalle +' ' + snum_ext + ' ' + snum_int + ' ' + scolonia + ' ' + smunicipio + ' ' + sciudad
        
        params= {
           'response_format': 'JSON', 
            'user' : 'desarrollo', 
            'reference': '12345',
            'currency' : 'MXN',
            'ammount' : smonto,
            'concept' : 'Prueba de pago', 
            'card_num'      :  snum_tarjeta, 
            'card_name'     :  snombre_completo,
            'card_type'     :  sid_tarjeta,
            'card_exp'      :  svencimiento,
            'card_ccv2'     :  snum_ccv,
            'address'       :  sdireccion_completa,
            'post_code'     :  scodigo_postal, 
            'phone'         :  stelefono,
            'mail'          :  semail
        }
        
        form_data = urllib.urlencode(params)
        """
        result = urlfetch.fetch(url=surl,
                                payload=form_data,
                                method=urlfetch.POST,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        """
        #sheaders={}
        result = urlfetch.fetch(url=surl, payload=form_data ,method=urlfetch.POST,  allow_truncated=False, follow_redirects=True, deadline=60, validate_certificate=None)
        #self.response.out.write(' Resultado: %s' % result.content)
        resultado=json.loads(result.content)
        r_user=resultado['user']
        r_id=resultado['id']
        r_referencia=resultado['referencia']
        r_date=resultado['date']
        r_card=resultado['card']
        r_response=resultado['response']
        r_code_auth=resultado['code_auth']
        r_monto=resultado['monto']
        r_client=resultado['client']
        self.response.out.write(r_response)
        

class confirmacionOxxo(BaseHandler):
    def get(self):
        self.response.out.write('Hello verificacion de pago')

class TestPagoOxxo(BaseHandler):
    def get(self):
        self.response.out.write('Hello world')
        surl="https://www.banwire.com/api.oxxo"
        params= {
            'usuario' : 'desarrollo', 
            'referencia': 'Z123X789Z',
            'dias_vigencia' : 3,
            'monto' : 12,
            'url_respuesta' : 'http://wishfan.com/confirmacionPago/', 
            'cliente'      :  'Roberto Iran Ramirez Norberto', 
            'formato'     :  'JSON',
            'sendPDF'     :True,
            'email'      :  'alexsmx@gmail.com'
        }
        form_data = urllib.urlencode(params)
        result = urlfetch.fetch(url=surl, payload=form_data ,method=urlfetch.POST,  allow_truncated=False, follow_redirects=True, deadline=60, validate_certificate=None)
        self.response.out.write(' Resultado: %s' % result.content)
        response = simplejson.loads(result.content)
        self.response.out.write(' response: %s' % response["error"])
        
        if response["error"]==False:
            barcode_img=response["response"]["barcode_img"]
            barcode= response["response"]["barcode"]
            referencia = response["response"]["referencia"]
            fecha_vigencia= response["response"]["fecha_vigencia"]
            monto=  response["response"]["monto"]
            pagooxodb= PagoOxxo(
                resp_cb= barcode,
                resp_referencia= referencia,
                resp_fecha_vigencia= fecha_vigencia,
                resp_monto= monto,
                resp_bc_img=base64.b64decode(barcode_img)
                )
            pagooxodb.put()
        
class imagenOxxo(BaseHandler):
    def get(self):
        id=self.request.GET.get("id")
        logging.info("Id: %s" % id)
        imagen= PagoOxxo.get_by_id(int(id))
        self.response.headers['Content-Type'] = 'image/png'
        self.response.out.write(imagen.resp_bc_img)
