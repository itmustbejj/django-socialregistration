import uuid

from django.conf import settings
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.utils.translation import gettext as _
from django.http import HttpResponseRedirect
import facebook

try:
    from django.views.decorators.csrf import csrf_protect
    has_csrf = True
except ImportError:
    has_csrf = False

from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib.sites.models import Site

from socialregistration.forms import UserForm
from socialregistration.utils import (OAuthClient, OAuthTwitter, OAuthLinkedin,
    OpenID, _https, DiscoveryFailure)
from socialregistration.models import SocialProfile, OpenIDProfile, \
        ST_LINKEDIN, ST_FACEBOOK, ST_TWITTER


FB_ERROR = _('We couldn\'t validate your Facebook credentials')

GENERATE_USERNAME = bool(getattr(settings, 'SOCIALREGISTRATION_GENERATE_USERNAME', False))

def _get_next(request):
    """
    Returns a url to redirect to after the login
    """
    if 'next' in request.session:
        next = request.session['next']
        del request.session['next']
        return next
    elif 'next' in request.GET:
        return request.GET.get('next')
    elif 'next' in request.POST:
        return request.POST.get('next')
    else:
        return getattr(settings, 'LOGIN_REDIRECT_URL', '/')

def setup(request, template='socialregistration/setup.html',
    form_class=UserForm, extra_context=dict()):
    """
    Setup view to create a username & set email address after authentication
    """
    try:
        social_user = request.session['socialregistration_user']
        social_profile = request.session['socialregistration_profile']
    except KeyError:
        return render_to_response(
            template, dict(error=True), context_instance=RequestContext(request))

    if not GENERATE_USERNAME:
        # User can pick own username
        if not request.method == "POST":
            form = form_class(social_user, social_profile)
        else:
            form = form_class(social_user, social_profile, request.POST)
            
            if form.is_valid():
                form.save(request=request)
                user = form.profile.authenticate()
                login(request, user)

                del request.session['socialregistration_user']
                del request.session['socialregistration_profile']

                return HttpResponseRedirect(_get_next(request))

        extra_context.update(dict(form=form))

        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))
        
    else:
        # Generate user and profile
        social_user.username = str(uuid.uuid4())[:30]
        social_user.save()

        social_profile.user = social_user
        social_profile.save()

        # Authenticate and login
        user = social_profile.authenticate()
        login(request, user)

        # Clear & Redirect
        del request.session['socialregistration_user']
        del request.session['socialregistration_profile']
        return HttpResponseRedirect(_get_next(request))

if has_csrf:
    setup = csrf_protect(setup)

def facebook_login(request, template='socialregistration/facebook.html',
    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    View to handle the Facebook login
    """
    
    fb_user = facebook.get_user_from_cookie(request.COOKIES,
        settings.FACEBOOK_API_KEY, settings.FACEBOOK_SECRET_KEY)

    if fb_user is None:
        extra_context.update(dict(error=FB_ERROR))
        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    user = authenticate(uid=fb_user['uid'], soc_type = ST_FACEBOOK)
    graph = facebook.GraphAPI(fb_user['access_token']).get_object(fb_user['uid'])

    if user is None:

        request.session['socialregistration_user'] = User()
        request.session['socialregistration_profile'] =\
                SocialProfile(
                        uid=fb_user['uid'],
                        username='%s %s' %(graph['first_name'], graph['last_name']),
                        avatar='http://graph.facebook.com/%s/picture' % fb_user['uid'],
                        soc_type = ST_FACEBOOK)
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        fb_profile = SocialProfile.objects.get(user=user, soc_type=ST_FACEBOOK)
        fb_profile.username='%s %s' %(graph['first_name'], graph['last_name'])
        fb_profile.save()
        return render_to_response(account_inactive_template, extra_context,
            context_instance=RequestContext(request))

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def facebook_connect(request, template='socialregistration/facebook.html',
    extra_context=dict()):
    """
    View to handle connecting existing django accounts with facebook
    """

    fb_user = facebook.get_user_from_cookie(request.COOKIES,
        settings.FACEBOOK_API_KEY, settings.FACEBOOK_SECRET_KEY)
    
    if fb_user is None or request.user.is_authenticated() is False:
        extra_context.update(dict(error=FB_ERROR))
        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))
    graph = facebook.GraphAPI(fb_user['access_token']).get_object(fb_user['uid'])

    try:
        profile = SocialProfile.objects.get(uid=fb_user['uid'],soc_type = ST_FACEBOOK)
    except SocialProfile.DoesNotExist:
        profile = SocialProfile.objects.create(user=request.user,
            uid=fb_user['uid'],
            username='%s %s' %(graph['first_name'], graph['last_name']),
            avatar='http://graph.facebook.com/%s/picture' % fb_user['uid'],
            soc_type = ST_FACEBOOK)
    else:
        profile.username='%s %s' %(graph['first_name'], graph['last_name']),
        profile.save()

    return HttpResponseRedirect(_get_next(request))

def logout(request, redirect_url=None):

    auth_logout(request)

    url = redirect_url or getattr(settings, 'LOGOUT_REDIRECT_URL', '/')

    return HttpResponseRedirect(url) 

def twitter(request, account_inactive_template='socialregistration/account_inactive.html',
    extra_context=dict()):
    """
    Actually setup/login an account relating to a twitter user after the oauth
    process is finished successfully
    """
    client = OAuthTwitter(
        request, settings.TWITTER_CONSUMER_KEY,
        settings.TWITTER_CONSUMER_SECRET_KEY,
        settings.TWITTER_REQUEST_TOKEN_URL,
    )

    user_info = client.get_user_info()

    try:
        profile = SocialProfile.objects.get(uid=user_info['id'], soc_type = ST_TWITTER)
    except SocialProfile.DoesNotExist: # There can only be one profile!
        profile = SocialProfile(
                uid=user_info['id'],
                username=user_info['screen_name'],
                avatar=user_info['profile_image_url'],
                soc_type=ST_TWITTER)
    else:
        profile.avatar = user_info['profile_image_url']
        profile.save()

    if request.user.is_authenticated():

        return HttpResponseRedirect(_get_next(request))

    user = authenticate(uid=user_info['id'], soc_type=ST_TWITTER)

    if user is None:

        user = User()
        request.session['socialregistration_profile'] = profile
        request.session['socialregistration_user'] = user
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        return render_to_response(
            account_inactive_template,
            extra_context,
            context_instance=RequestContext(request)
        )

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def linkedin(request):
    """
    Actually setup/login an account relating to a linkedin user after the oauth 
    process is finished successfully
    """
    client = OAuthLinkedin(
        request, settings.LINKEDIN_CONSUMER_KEY,
        settings.LINKEDIN_CONSUMER_SECRET_KEY,
        settings.LINKEDIN_REQUEST_TOKEN_URL,
    )
    
    user_info = client.get_user_info()

    user = authenticate(uid=user_info['id'], soc_type = ST_LINKEDIN)

    if user is None:
        profile = SocialProfile(uid=user_info['id'],
                    username=user_info['screen_name'],
                    avatar=user_info['profile_image_url'],
                    soc_type = ST_LINKEDIN)
        user = User()
        request.session['socialregistration_profile'] = profile
        request.session['socialregistration_user'] = user
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    login(request, user)
    request.user.message_set.create(message=_('You have succesfully been logged in with your linkedin account'))
    
    return HttpResponseRedirect(_get_next(request))

def oauth_redirect(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, parameters=None):
    """
    View to handle the OAuth based authentication redirect to the service provider
    """
    request.session['next'] = _get_next(request)
    client = OAuthClient(request, consumer_key, secret_key,
        request_token_url, access_token_url, authorization_url, callback_url, parameters)
    return client.get_redirect()

def oauth_callback(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, template='socialregistration/oauthcallback.html',
    extra_context=dict(), parameters=None):
    """
    View to handle final steps of OAuth based authentication where the user
    gets redirected back to from the service provider
    """
    if 'oauth_verifier' in request.REQUEST:
        parameters = 'oauth_verifier='+request.REQUEST['oauth_verifier']
    client = OAuthClient(request, consumer_key, secret_key, request_token_url,
        access_token_url, authorization_url, callback_url, parameters)

    extra_context.update(dict(oauth_client=client))

    if not client.is_valid():
        return render_to_response(
            template, extra_context, context_instance=RequestContext(request)
        )

    # We're redirecting to the setup view for this oauth service
    return HttpResponseRedirect(reverse(client.callback_url))

def openid_redirect(request):
    """
    Redirect the user to the openid provider
    """
    request.session['next'] = _get_next(request)
    request.session['openid_provider'] = request.GET.get('openid_provider')
    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            request.get_host(),
            reverse('openid_callback')
        ),
        request.GET.get('openid_provider')
    )
    try:
        return client.get_redirect()
    except DiscoveryFailure:
        request.session['openid_error'] = True
        return HttpResponseRedirect(settings.LOGIN_URL)

def openid_callback(request, template='socialregistration/openid.html',
    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    Catches the user when he's redirected back from the provider to our site
    """
    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            request.get_host(),
            reverse('openid_callback')
        ),
        request.session.get('openid_provider')
    )
    if client.is_valid():
        identity = client.result.identity_url
        if request.user.is_authenticated():
            # Handling already logged in users just connecting their accounts
            try:
                profile = OpenIDProfile.objects.get(identity=identity)
            except OpenIDProfile.DoesNotExist: # There can only be one profile with the same identity
                profile = OpenIDProfile.objects.create(user=request.user,
                    identity=identity)

            return HttpResponseRedirect(_get_next(request))

        user = authenticate(identity=identity)
        if user is None:
            request.session['socialregistration_user'] = User()
            request.session['socialregistration_profile'] = OpenIDProfile(
                identity=identity
            )
            return HttpResponseRedirect(reverse('socialregistration_setup'))

        if not user.is_active:
            return render_to_response(
                account_inactive_template,
                extra_context,
                context_instance=RequestContext(request)
            )

        login(request, user)
        return HttpResponseRedirect(_get_next(request))

    return render_to_response(
        template,
        dict(),
        context_instance=RequestContext(request)
    )

