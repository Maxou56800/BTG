#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is part of BTG.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

import json
import urllib.parse
import re

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

cfg = Config.get_instance()


class FortiguardWebFilter:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL", "domain", "IPv4"]
        self.search_method = "Online"
        self.description = "Search IOC in FortiGuardWebFilter database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = True
        self.headers = self.config["user_agent"]
        self.fortios_version = "9"

        self.Search()

    def Search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in FortiguardWebFilter...")
        url = 'https://www.fortiguard.com/webfilter?&version={}&q={}'.format(self.fortios_version, urllib.parse.quote(self.ioc))
        request = {
            'url': url,
            'headers': self.headers,
            'module': self.module_name,
            'ioc': self.ioc,
            'ioc_type': self.type,
            'verbose': self.verbose,
            'proxy': self.proxy,
            'verify': self.verify,
        }
        json_request = json.dumps(request)
        store_request(self.queues, json_request)

def response_handler(response_text, response_status, module, ioc, ioc_type, server_id):
    if response_status == 200:
        ioc_category = re.findall('<meta name="description" property="description" content="Category: (.*)"', response_text)
        if not len(ioc_category): 
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "Not category for this IOC"
            )
            return None
        # Categories extract from: https://www.fortiguard.com/webfilter/categories
        risk_categories = [
            "Dynamic DNS",
            "Malicious Websites",
            #"Newly Observed Domain", # Too many false positive
            "Newly Registred Domain",
            "Phishing",
            "Spam URLs",
            "Proxy Avoidance", # Tor related (Not in risk category)
        ]
        if ioc_category[0] not in risk_categories:
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "This IOC is not in a security risk category: {}".format(ioc_category[0])
            )
            return None
        
        mod.display(module,
                    ioc,
                    "FOUND",
                    "Category: {}".format(ioc_category[0])
        )
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="urlscan connection status : %d" % (response_status))
