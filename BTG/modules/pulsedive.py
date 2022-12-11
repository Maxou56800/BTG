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
import random
import urllib.parse

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

cfg = Config.get_instance()


class Pulsedive:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "IPv6", "domain", "URL"]
        self.search_method = "Online"
        self.description = "Search IOC in Pulsedive database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = True
        self.headers = self.config["user_agent"]
        if self.type not in self.types:
            return None
        if len(self.config['pulsedive_api_keys']) == 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "Pulsedive fields in btg.cfg are missfilled, checkout commentaries.")
            return None
        # Use random key
        pulsedive_key = random.Random(self.ioc).choice(self.config['pulsedive_api_keys'])
        self.Search(pulsedive_key)

    def Search(self, pulsedive_api_key):
        mod.display(self.module_name, "", "INFO", "Search in Pulsedive...")
        self.headers["Accept"] = "application/json"
        query = urllib.parse.quote("ioc={}".format(self.ioc))
        url = "https://pulsedive.com/api/explore.php?&pretty=1&limit=1&key={}&q={}".format(pulsedive_api_key, query)
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

def get_color(risk):
    risk = risk.upper()
    if risk == "LOW":
        return "{}{}{}{}".format(
            colors.LOW_RISK,
            risk,
            colors.NORMAL,
            colors.BOLD
        )
    elif risk == "MEDIUM":
        return "{}{}{}{}".format(
            colors.MEDIUM_RISK,
            risk,
            colors.NORMAL,
            colors.BOLD
        )
    elif risk == "HIGH":
        return "{}{}{}{}".format(
            colors.HIGH_RISK,
            risk,
            colors.NORMAL,
            colors.BOLD
        )
    else:
        return risk

def response_handler(response_text, response_status, module, ioc, ioc_type, server_id):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="Pulsedive json_response was not readable.")
            return None
        if not len(json_response["results"]):
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "This addresse IOC not listed in Pulsedive")
            return None
        if json_response["results"][0]["risk"].lower() == "none":
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "This addresse IOC seem to be clean for Pulsedive (risk: none)")
            return None

        mod.display(module,
                    ioc,
                    "FOUND",
                    "Risk: {} | Details URL: https://pulsedive.com/indicator/?iid={}".format(
                        get_color(json_response["results"][0]["risk"]),
                        json_response["results"][0]["iid"]
                    )
        )
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="Pulsedive connection status : %d" % (response_status))
