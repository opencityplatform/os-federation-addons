#  Copyright (c) 2014 INFN - "Istituto Nazionale di Fisica Nucleare" - Italy
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License. 

import logging
import urlparse
import urllib

from django import shortcuts
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.utils.translation import ugettext as _

from django.contrib.auth.decorators import login_required
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators import vary

from openstack_auth.views import login as basic_login
from openstack_auth.views import logout as basic_logout
from openstack_auth.views import switch as basic_switch
from openstack_auth.views import switch_region as basic_switch_region
from openstack_auth.user import set_session_from_user
from openstack_auth.user import create_user_from_token
from openstack_auth.user import Token
from openstack_auth.exceptions import KeystoneAuthException
from openstack_auth.forms import Login as login_form 
from .backend import ExtClient

try:
    from django.utils.http import is_safe_url
except ImportError:
    from openstack_auth.utils import is_safe_url

from openstack_auth.views import delete_token

from horizon import forms, get_user_home

from .forms import TokenForm


LOG = logging.getLogger(__name__)

def get_ostack_attributes(request):
    region = getattr(settings, 'OPENSTACK_KEYSTONE_URL').replace('v2.0','v3')
    domain = getattr(settings, 'OPENSTACK_KEYSTONE_DEFAULT_DOMAIN', 'Default')
    return (domain, region)

@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    return basic_login(request)

def logout(request):

    if 'os_federation_proto' in request.session \
        and request.session['os_federation_proto'] == "SAML2":
        
        endpoint = request.session.get('region_endpoint')
        token = request.session.get('token')
        if token and endpoint:
            delete_token(endpoint=endpoint, token_id=token.id)

        auth_logout(request)
        #
        # TODO this is a local shibboleth logout
        #
        logout_url = '/Shibboleth.sso/Logout?return=https://%s:%s/dashboard' % \
            (request.META['SERVER_NAME'], request.META['SERVER_PORT'])
        response = shortcuts.redirect(logout_url)
    else:
        response = basic_logout(request)
    
    response.delete_cookie('logout_reason')
    return response


@login_required
def switch(request, tenant_id, redirect_field_name=REDIRECT_FIELD_NAME):
    if 'os_federation_proto' in request.session:
        try:
            endpoint = request.user.endpoint.replace('v2.0', 'v3')
            client = ExtClient(raw_token=request.session['unscoped_token'],
                                project_id=tenant_id,
                                auth_url=endpoint,
                                insecure=getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False),
                                cacert=getattr(settings, 'OPENSTACK_SSL_CACERT', None),
                                debug=settings.DEBUG)
            auth_ref = client.auth_ref
            
            redirect_to = request.REQUEST.get(redirect_field_name, '')
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = settings.LOGIN_REDIRECT_URL
            if auth_ref:
                old_endpoint = request.session.get('region_endpoint')
                old_token = request.session.get('token')
                if old_token and old_endpoint and old_token.id != auth_ref.auth_token:
                    delete_token(endpoint=old_endpoint, token_id=old_token.id)
                user = create_user_from_token(request, Token(auth_ref), endpoint)
                set_session_from_user(request, user)
            return shortcuts.redirect(redirect_to)

        except:
            LOG.error("Failed to switch to new project", exc_info=True)
            return shortcuts.redirect('/dashboard')

    return basic_switch(request, tenant_id, redirect_field_name)

def switch_region(request, region_name, redirect_field_name=REDIRECT_FIELD_NAME):
    return basic_switch_region(request, region_name, redirect_field_name)

@sensitive_post_parameters()
@csrf_exempt
@never_cache
def authtoken(request):

    if request.method == 'POST':
        
        domain, region = get_ostack_attributes(request)
        
        auth_form = TokenForm(request.POST)
        if auth_form.is_valid():
        
            try:
                if auth_form.cleaned_data['pcode']:
                    raise KeystoneAuthException("Cannot authenticate user with token")
                
                user = authenticate(request=request,
                                    rawtoken=auth_form.cleaned_data['token'],
                                    auth_url=region)
            
                auth_login(request, user)
                if request.user.is_authenticated():
                    set_session_from_user(request, request.user)
                
                    default_region = (settings.OPENSTACK_KEYSTONE_URL, "Default Region")
                    regions = dict(getattr(settings, 'AVAILABLE_REGIONS', [default_region]))
                
                    region = request.user.endpoint
                    region_name = regions.get(region)
                    request.session['region_endpoint'] = region
                    request.session['region_name'] = region_name
                    request.session['os_federation_proto'] = auth_form.cleaned_data['proto']
                    
                    return shortcuts.redirect('/dashboard/project')
                
            except:
                LOG.error("Failed authentication", exc_info=True)
        else:
            LOG.error("Authetication form is not valid")
    
    response = shortcuts.redirect('/dashboard')
    response.set_cookie('logout_reason', 'User invalid or not authenticated')
    return response

def get_fedkeystone_url():
    fed_keystone_url = getattr(settings, 'OPENSTACK_FED_KEYSTONE_URL', None)
    if not fed_keystone_url:
        tmptpl = urlparse.urlparse(settings.OPENSTACK_KEYSTONE_URL)
        fed_keystone_url = "%s://%s" % (tmptpl.scheme, tmptpl.hostname)
    return fed_keystone_url

@vary.vary_on_cookie
def splash(request):

    if request.user.is_authenticated():
        return shortcuts.redirect(get_user_home(request.user))
        
    form = login_form(request)
    request.session.clear()
    request.session.set_test_cookie()
    
    fed_keystone_url = get_fedkeystone_url()
    tmplist = list()
    for item in settings.HORIZON_CONFIG.get('identity_providers', []):
        #
        # TODO check idp list well-formedness
        #
        return_query = urllib.urlencode({
            'return' : 'https://%s:%s/dashboard/auth/authtoken/' % \
            (request.META['SERVER_NAME'], request.META['SERVER_PORT'])
        })
        target = '%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth?%s' % \
            (
                settings.OPENSTACK_KEYSTONE_URL, 
                item['idpId'], 
                item['protocolId'],
                return_query
            )
        tmpquery = urllib.urlencode({
            'entityID' : item['entityId'],
            'target' : target
        })

        tmplist.append({
            'path' : "%s/Shibboleth.sso/Login?%s" % (fed_keystone_url, tmpquery),
            'description' : item['description'],
            'logo' : item['logo']
        })
    
    return shortcuts.render(request, 'splash.html', {'form': form, 'idplist' : tmplist})


