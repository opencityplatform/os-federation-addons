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

from django.conf import settings
from django.utils.translation import ugettext as _

from keystoneclient.exceptions import AuthorizationFailure
from keystoneclient.v3.client import Client as BaseClient

from keystoneclient.v3.projects import Project as ProjectRes

from openstack_auth import backend as base_backend
from openstack_auth.exceptions import KeystoneAuthException
from openstack_auth.user import create_user_from_token
from openstack_auth.user import Token


LOG = logging.getLogger(__name__)


class ExtClient(BaseClient):

    def __init__(self, **kwargs):   
        if 'raw_token' in kwargs:
            self.raw_token = kwargs['raw_token']
            del kwargs['raw_token']
        else:
            self.raw_token = None
        super(ExtClient, self).__init__(**kwargs)

    def get_raw_token_from_identity_service(self, auth_url, user_id=None,
                                            username=None,
                                            user_domain_id=None,
                                            user_domain_name=None,
                                            password=None,
                                            domain_id=None, domain_name=None,
                                            project_id=None, project_name=None,
                                            project_domain_id=None,
                                            project_domain_name=None,
                                            token=None,
                                            trust_id=None,
                                            **kwargs):


        if self.raw_token == None:
            return super(ExtClient, self).get_raw_token_from_identity_service(
                                                   auth_url, user_id, username,
                                                   user_domain_id, user_domain_name,
                                                   password, domain_id, domain_name,
                                                   project_id, project_name,
                                                   project_domain_id,
                                                   project_domain_name, token,
                                                   trust_id)
        try:
            main_tenant_id = None
            main_domain_id = None
            
            headers = {'Accept' : 'application/json', 'X-Auth-Token' : self.raw_token}
            url = auth_url + "/OS-FEDERATION/projects"
            resp, body = self.request(url, 'GET', headers=headers)
        
            prj_list = body.get('projects', None)
            if prj_list and project_id:
                for p_item in prj_list:
                    if p_item['id'] == project_id:
                        main_tenant_id = project_id
                        main_domain_id = p_item['domain_id']
                if main_tenant_id == None:
                    raise AuthorizationFailure("Cannot find required project for user")
            elif prj_list:
                main_tenant_id = prj_list[0]['id']
                main_domain_id = prj_list[0]['domain_id']
            else:
                raise AuthorizationFailure("Cannot find any project for user")

            headers = {'Accept' : 'application/json'}
            url = auth_url + "/auth/tokens"
            body = {'auth': {'identity': {}, 'scope' : {}}}
            
            ident = body['auth']['identity']
            ident['methods'] = ['saml2']
            ident['saml2'] = {'id' : self.raw_token}
            
            body['auth']['scope']['project'] = {
                "id" : main_tenant_id, 
                'domain' : {'id' : main_domain_id}
            }
            
            #
            # TODO verify workaround in keystone/token/providers/common.py (504)
            #
            resp, body = self.request(url, 'POST', body=body, headers=headers)
            return resp, body

        except:
            LOG.error("Cannot get scoped token", exc_info=True)
        raise AuthorizationFailure("Cannot get scoped token")        

#
# Register this backend in /usr/share/openstack-dashboard/openstack_dashboard/settings.py
# AUTHENTICATION_BACKENDS = ('openstack_auth_shib.backend.ExtKeystoneBackend',)
#
class ExtKeystoneBackend(base_backend.KeystoneBackend):

    def _convert_tlist(self, tlist):
        result = list()
        for prj_dict in tlist:
            result.append(ProjectRes(None, prj_dict, True))
        return result
        

    def get_user(self, user_id):
        user = super(ExtKeystoneBackend, self).get_user(user_id)
        if (user and hasattr(self, 'request') 
            and 'fed_projects' in self.request.session):
            user.authorized_tenants = self._convert_tlist(self.request.session['fed_projects'])
        return user


    def authenticate(self, request=None, username=None, password=None,
                     user_domain_name=None, auth_url=None, rawtoken=None):
        
        insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
        cacert = getattr(settings, 'OPENSTACK_SSL_CACERT', None)
        ep_type = getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'publicURL')
        secret_key = getattr(settings, 'SECRET_KEY', None)
        
        #
        # Authetication with username and password
        #
        if password:
            parentObj = super(ExtKeystoneBackend, self)
            return parentObj.authenticate(request, username, password,
                                          user_domain_name, auth_url)
        
        #
        # Authetication with os-federation token
        #
        if not rawtoken:
            raise KeystoneAuthException('Missing unscoped token')
            
        try:
            client = ExtClient(raw_token=rawtoken,
                               auth_url=auth_url,
                               insecure=insecure,
                               cacert=cacert,
                               debug=settings.DEBUG)
            auth_ref = client.auth_ref
        
            headers = {'Accept' : 'application/json', 'X-Auth-Token' : rawtoken}
            url = auth_url + "/OS-FEDERATION/projects"
            resp, body = client.request(url, 'GET', headers=headers)
        
            if 'projects' in body:
                request.session['fed_projects'] = body['projects']

            project_token = Token(auth_ref)
            user = create_user_from_token(request, project_token,
                                          client.service_catalog.url_for(endpoint_type=ep_type))
            user.authorized_tenants = self._convert_tlist(request.session['fed_projects'])
            
            if request is not None:
                request.session['unscoped_token'] = rawtoken
                request.user = user

                # Support client caching to save on auth calls.
                setattr(request, base_backend.KEYSTONE_CLIENT_ATTR, client)
            
            return user
            
        except:
            LOG.error("Failed to get scoped token", exc_info=True)
            raise KeystoneAuthException("Cannot authenticate user with token")


