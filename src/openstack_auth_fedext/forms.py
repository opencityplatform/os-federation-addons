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

from horizon import forms
from django.utils.translation import ugettext as _


LOG = logging.getLogger(__name__)

class TokenForm(forms.Form):

    def __init__(self, *args, **kwargs):
        super(TokenForm, self).__init__(*args, **kwargs)

        self.fields['token'] = forms.CharField(label=_('Token'))
        self.fields['proto'] = forms.CharField(label=_('Protocol'))
        self.fields['pcode'] = forms.IntegerField(label=_('Process Code'))


