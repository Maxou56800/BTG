#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2018 Tanguy Becam
#
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
import random

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod


class googlesb():
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL", "domain"]
        # googleSB can run on a local database with a 30min refresh by default
        self.search_method = "Online"
        self.description = "Search IOC in GoogleSafeBrowsing database"
        self.author = "Conix"
        self.creation_date = "11-04-2018"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        self.lookup_API()

    def lookup_API(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in Google Safe Browsing ...")

        if 'googlesb_api_keys' in self.config:
            try:
                api_key = random.Random(self.ioc).choice(self.config['googlesb_api_keys'])
            except:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="Check if you have filled googlesb_api_keys in btg.cfg")
                return None
        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="Check if you have googlesb_api_keys field in btg.cfg")
            return None

        self.url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+api_key

        # TODO
        # Does not work 400 status_code
        if self.type == "SHA256":
            threatType = "EXECUTABLE"
            threatTypeEntry = "hash"
        # Does not work 400 status_code
        elif self.type in ["IPv4", "IPv6"]:
            threatType = "IP_RANGE"
            threatTypeEntry = "ip"
        else:
            threatType = "URL"

        payload = {"threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                                  "platformTypes": ["ANY_PLATFORM", "ALL_PLATFORMS", "WINDOWS", "LINUX", "OSX", "ANDROID", "IOS"],
                                  "threatEntryTypes": [threatType],
                                  "threatEntries": [{threatType.lower(): str(self.ioc)}]
                                  }
                   }
        self.data = json.dumps(payload)
        request = {'url': self.url,
                   'headers': self.headers,
                   'data': self.data,
                   'module': self.module_name,
                   'ioc': self.ioc,
                   'ioc_type': self.type,
                   'verbose': self.verbose,
                   'proxy': self.proxy
                   }
        json_request = json.dumps(request)
        store_request(self.queues, json_request)

def research_finished(module, ioc, message=""):
    mod.display(module,
                    ioc,
                    "FINISHED")
    return

def response_handler(response_text, response_status, module,
                     ioc, ioc_type, server_id=None):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="GoogleSafeBrowsing json_response was not readable.")
            research_finished(module, ioc)
            return None

        if 'matches' in json_response:
            list_platform = set([])
            list_type = set([])
            for m in json_response['matches']:
                list_type.add(m['threatType'])
                list_platform.add(m['platformType'])
            mod.display(module,
                        ioc,
                        message_type="FOUND",
                        string="ThreatType: %s | PlatformType: %s" % (list_type, list_platform))
        else:
            mod.display(module,
                        ioc,
                        message_type="NOT_FOUND",
                        string="Nothing found in Google Safe Browsing")
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="GoogleSafeBrowsing connection status : %d" % (response_status))
    research_finished(module, ioc)
    return None
