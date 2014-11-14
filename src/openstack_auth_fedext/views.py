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

from django import shortcuts
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.utils.translation import ugettext as _

from django.contrib.auth.decorators import login_required
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt

from openstack_auth.views import login as basic_login
from openstack_auth.views import logout as basic_logout
from openstack_auth.views import switch as basic_switch
from openstack_auth.views import switch_region as basic_switch_region
from openstack_auth.user import set_session_from_user
from openstack_auth.user import create_user_from_token
from openstack_auth.user import Token
from .backend import ExtClient

try:
    from django.utils.http import is_safe_url
except ImportError:
    from openstack_auth.utils import is_safe_url

from openstack_auth.views import delete_token

from horizon import forms

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
        logout_url = '/Shibboleth.sso/Logout?return=https://%s:%s/dashboard' % \
            (request.META['SERVER_NAME'], request.META['SERVER_PORT'])
        return shortcuts.redirect(logout_url)
        
    return basic_logout(request)


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
        LOG.info("Called POST for authtoken")
        
        domain, region = get_ostack_attributes(request)
        
        auth_form = TokenForm(request.POST)
        if auth_form.is_valid():
        
            try:
                LOG.debug("Calling autheticate with token")
                user = authenticate(request=request,
                                    rawtoken=auth_form.cleaned_data['token'],
                                    auth_url=region)
            
                auth_login(request, user)
                if request.user.is_authenticated():
                    LOG.debug('User autheticated %s' % request.user.username)
                    set_session_from_user(request, request.user)
                
                    default_region = (settings.OPENSTACK_KEYSTONE_URL, "Default Region")
                    regions = dict(getattr(settings, 'AVAILABLE_REGIONS', [default_region]))
                
                    region = request.user.endpoint
                    region_name = regions.get(region)
                    request.session['region_endpoint'] = region
                    request.session['region_name'] = region_name
                    
                    #
                    # TODO protocol SAML2 hard-coded
                    #
                    request.session['os_federation_proto'] = "SAML2"
                else:
                    LOG.debug('User not autheticated %s' % request.user.username)
            
                return shortcuts.redirect('/dashboard/project')
                
            except:
                LOG.error("Failed authentication", exc_info=True)
        else:
            #
            # TODO handle error
            #
            LOG.error("Authetication form is not valid")
        
    return shortcuts.redirect('/dashboard')


