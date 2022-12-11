#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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

import re
import json

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod
from BTG.lib.io import colors

class Virusshare:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256"]
        self.search_method = "Online"
        self.description = "Search IOC malware in VirusShare"
        self.author = "Hicham Megherbi"
        self.creation_date = "15-11-2017"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]
        self.search()

    def search(self):
        if "virusshare_apikey" not in self.config:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "You must specify an API key in btg.cfg")
            return None
        self.apikey = self.config['virusshare_apikey']
        self.url = "https://virusshare.com/apiv2/file?apikey={}&hash={}".format(self.apikey, self.ioc)

        request = {
            'url': self.url,
            'headers': self.headers,
            'module': self.module_name,
            'ioc': self.ioc,
            'ioc_type': self.type,
            'verbose': self.verbose,
            'proxy': self.proxy
        }

        json_request = json.dumps(request)
        store_request(self.queues, json_request)

def get_color(positives):
    if positives == 0:
        return "{}{}{}{}".format(
            colors.GOOD,
            positives,
            colors.NORMAL,
            colors.BOLD
        )
    return "{}{}{}{}".format(
            colors.INFECTED,
            positives,
            colors.NORMAL,
            colors.BOLD
        )

def response_handler(response_text, response_status,
                     module, ioc, ioc_type, server_id=None, ):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "VirusShare json_response was not readable.")
            return None

        if "response" in json_response and json_response["response"] == 0:
                mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "VirusShare unable to reply a response")
                return None
        
        url_result = "https://virusshare.com/file?{}".format(json_response["sha256"])
        mod.display(module,
                    ioc,
                    "FOUND",
                    "AV {}/{} | {}".format(
                        get_color(json_response["virustotal"]["positives"]),
                        len(json_response["virustotal"]["scans"]),
                        url_result))
    elif response_status == 204:
        mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "No hash found")
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MetaDefender response.code_status : %d" % (response_status))
        return None
    return None