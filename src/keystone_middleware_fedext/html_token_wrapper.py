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

import six

from keystone.common.config import CONF
from keystone.common import wsgi
from keystone.openstack.common import log

LOG = log.getLogger(__name__)

html_template = '''<html>
  <head>
    <meta content='text/html; charset=utf-8' http-equiv='Content-Type' />
    <title>Redirect for %(user)s</title>
  </head>
  <body onload="document.forms[0].submit()">
    <noscript>
      <p>
        <strong>Note:</strong> Since your browser does not support JavaScript,
        you must press the Continue button once to proceed.
     </p>
    </noscript>
    
    <form method="POST" action="%(url)s">
      <input type="hidden" name="pcode" value="%(pcode)d"/>
      <input type="hidden" name="token" value="%(token)s"/>
      <noscript>
        <div><input type="submit" value="Continue"/></div>
      </noscript>
    </form>
  </body>
</html>
'''

class TokenWrapperMiddleware(wsgi.Middleware):

    def __init__(self, *args, **kwargs):
        super(TokenWrapperMiddleware, self).__init__(*args, **kwargs)

    def process_response(self, request, response):
        querystr = dict(six.iteritems(request.params))
        if 'return' in querystr:
            res_headers = dict(six.iteritems(response.headers))
            
            response.content_type = 'text/html'
            response.charset = 'UTF-8'
            
            if 'X-Subject-Token' in res_headers:
                
                response.text = html_template % {
                    'url' : querystr['return'], 
                    'pcode' : 0,
                    'token' : res_headers['X-Subject-Token'],
                    'user' : request.environ.get('REMOTE_USER', 'Unknown')
                }
                
            else:
                response.text = html_template % {
                    'url' : querystr['return'], 
                    'pcode' : 1,
                    'token' : '',
                    'user' : request.environ.get('REMOTE_USER', 'Unknown')
                }

        return response

