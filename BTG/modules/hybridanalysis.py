#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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

import random
import json

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod
from BTG.lib.io import colors

class HybridAnalysis:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "domain", "IPv4", "IPv6", "URL"]
        self.search_method = "Online"
        self.description = "Search IOC in Hybrid Analysis"
        self.author = "Hicham Megherbi"
        self.creation_date = "20-10-2017"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        # Specifing user_agent to avoid the 403
        self.headers = {'User-agent': 'Falcon Sandbox',
                        'Content-type': 'application/x-www-form-urlencoded',
                        'accept': 'application/json'}
        self.proxy = self.config["proxy_host"]

        self.hybridanalysis_api()

    def hybridanalysis_api(self):
        """
            hybridanalysis API Connection
        """

        if 'hybridanalysis_api_keys' in self.config:
            try:
                self.headers['api-key'] = random.Random(self.ioc).choice(self.config['hybridanalysis_api_keys'])
            except:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Check if you have filled hybridanalysis_api_keys_secret in btg.cfg")
                return None
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "Check if you have hybridanalysis_api_keys_secret field in btg.cfg")
            return None

        if self.type in ["MD5", "SHA1", "SHA256"]:
            self.url = "https://www.hybrid-analysis.com/api/v2/search/hash"
            self.data = "hash="+self.ioc
        else:
            self.url = "https://www.hybrid-analysis.com/api/v2/search/terms"
            if self.type in ["IPv4", "IPv6"]:
                self.data = "host="+self.ioc
            elif self.type == "URL":
                self.data = "url="+self.ioc
            else:
                self.data = "domain="+self.ioc

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

def get_color_verdict(verdict):
    if verdict == "Malicious":
        return "{}{}{}{}".format(
                colors.INFECTED,
                verdict,
                colors.NORMAL,
                colors.BOLD
        )
    elif verdict == "Suspicious":
        return "{}{}{}{}".format(
            colors.SUSPICIOUS,
            verdict,
            colors.NORMAL,
            colors.BOLD
        )
    else:
        return verdict

def get_color_positives(positives):
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
                     module, ioc, ioc_type, server_id=None):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="hybridanalysis json_response was not readable.")
            return None

        if "count" in json_response and "search_terms" in json_response:
            if json_response["count"] > 0:
                verdict = json_response["result"][0]["verdict"]
                threat_score = json_response["result"][0]["threat_score"]
                if ioc_type in ["domain", "IPv4", "IPv6", "URL"] and (threat_score == None or "no specific threat" in verdict):
                    mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "No specific threat found in hybridanalysis")
                    return None
                type = json_response["search_terms"][0]["id"]
                url = "https://www.hybrid-analysis.com/advanced-search-results?terms[%s]=%s" % (type, ioc)
                mod.display(module,
                            ioc,
                            "FOUND",
                            "%s | %s/100 | %s" % (verdict, threat_score, url))
                return None
        elif json_response:
            verdict = json_response[0]["verdict"]
            threat_score = json_response[0]["threat_score"]
            if ioc_type in ["domain", "IPv4", "IPv6", "URL"] and (threat_score == None or "no specific threat" in verdict):
                mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "No specific threat found in hybridanalysis")
                return None
            url = "https://www.hybrid-analysis.com/sample/"+ioc
            display_array = []
            display_array.append(get_color_verdict(verdict.capitalize()))
            if threat_score == None:
                threat_score_message = ""
            else: 
                threat_score_message = "{}/100".format(get_color_positives(threat_score))
                display_array.append(threat_score_message)
            display_array.append("Details: {}".format(url))
            mod.display(module,
                        ioc,
                        "FOUND",
                        " | ".join(display_array))
            return None
        mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "Nothing found in hybridanalysis DB")
        return None
    else:
        mod.display(module,
                    ioc,
                    "ERROR",
                    "hybridanalysis API connection status %d" % response_status)
        return None
