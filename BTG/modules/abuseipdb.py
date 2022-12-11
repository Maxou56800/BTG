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

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

cfg = Config.get_instance()


class AbuseIPDB:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search IOC in AbuseIPDB database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = True
        self.headers = self.config["user_agent"]
        if self.type not in self.types:
            return None
        if len(self.config['abuseipdb_api_keys']) == 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "AbuseIPDB fields in btg.cfg are missfilled, checkout commentaries.")
            return None
        # Use random key
        abuseipdb_key = random.Random(self.ioc).choice(self.config['abuseipdb_api_keys'])
        self.Search(abuseipdb_key)

    def Search(self, abuseipdb_api_key):
        mod.display(self.module_name, "", "INFO", "Search in AbuseIPDB...")
        self.headers["Accept"] = "application/json"
        self.headers["Key"] = abuseipdb_api_key
        url = "https://api.abuseipdb.com/api/v2/check?ipAddress={}".format(self.ioc)
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

def response_handler(response_text, response_status, module, ioc, ioc_type, server_id):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="AbuseIPDB json_response was not readable.")
            return None
        if json_response["data"]["totalReports"] == 0 and json_response["data"]["abuseConfidenceScore"] == 0:
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "This addresse IP seem to be clean for AbuseIPDB")
            return None
        mod.display(module,
                    ioc,
                    "FOUND",
                    "Confidence of abuse is {}% | Total reports: {} from {} distinct users | Details URL: {}".format(
                        get_color(json_response["data"]["abuseConfidenceScore"]),
                        get_color(json_response["data"]["totalReports"]),
                        json_response["data"]["numDistinctUsers"],
                        "https://www.abuseipdb.com/check/{}".format(ioc)
                    )
        )
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="AbuseIPDB connection status : %d" % (response_status))
