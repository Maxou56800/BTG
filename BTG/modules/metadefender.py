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
import base64

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod
from BTG.lib.io import colors

class metadefender:
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "SHA512", "domain", "URL", "IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search IOC in MetaDefender"
        self.author = "Conix"
        self.creation_date = "13-04-2018"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        self.Search()

    def Search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in MetaDefender ...")
        try:
            if 'metadefender_api_keys' in self.config:
                try:
                    api_key = random.Random(self.ioc).choice(self.config['metadefender_api_keys'])
                    self.headers['apikey'] = api_key
                except:
                    mod.display(self.module_name,
                                self.ioc,
                                message_type="ERROR",
                                string="Check if you have filled metadefender_api_keys in btg.cfg")
                    return None
            else:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="Check if you have metadefender_api_keys field in btg.cfg")
                return None
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your MetaDefender key")
            return None

        # URL building
        self.url = "https://api.metadefender.com"
        if self.type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            self.url = "{}/v4/hash/{}".format(self.url , self.ioc)
        elif self.type == "domain":
            self.url = "{}/v4/domain/{}".format(self.url , self.ioc)
        elif self.type == "URL":
            self.url = "{}/v4/url/{}".format(self.url , self.ioc)
        elif self.type in ["IPv4", "IPv6"]:
            self.url = "{}/v4/ip/{}".format(self.url , self.ioc)

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

def research_finished(module, ioc, message=""):
    mod.display(module,
                    ioc,
                    "FINISHED")
    return

def response_handler(response_text, response_status,
                     module, ioc, ioc_type, server_id=None, ):
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "MetaDefender json_response was not readable.")
            research_finished(module, ioc)
            return None

        if ioc_type == "URL":
            url_result = "https://metadefender.opswat.com/results/url/{}/overview"
            if json_response["lookup_results"]["detected_by"] == 0:
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Zero AV detected malicious activity")
                research_finished(module, ioc)
                return None
            mod.display(module,
                        ioc,
                        "FOUND",
                        "AV {}/{} | {}".format(
                            get_color(json_response["lookup_results"]["detected_by"]),
                            len(json_response["lookup_results"]["sources"]),
                            url_result.format(base64.b64encode(ioc.encode()).decode())))

        if ioc_type == "domain":
            url_result = "https://metadefender.opswat.com/results/domain/{}/overview"
            if json_response["lookup_results"]["detected_by"] == 0:
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Zero AV detected malicious activity")
                research_finished(module, ioc)
                return None
            mod.display(module,
                        ioc,
                        "FOUND",
                        "AV {}/{} | {}".format(
                            get_color(json_response["lookup_results"]["detected_by"]),
                            len(json_response["lookup_results"]["sources"]),
                            url_result.format(base64.b64encode(ioc.encode()).decode())))
        elif ioc_type in ["IPv4", "IPv6"]:
            url_result = "https://metadefender.opswat.com/results/ip/{}/overview"
            if json_response["lookup_results"]["detected_by"] == 0:
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Zero AV detected malicious activity")
                research_finished(module, ioc)
                return None
            mod.display(module,
                        ioc,
                        "FOUND",
                        "AV {}/{} | Country: {} | City: {} | {}".format(
                            get_color(json_response["lookup_results"]["detected_by"]),
                            len(json_response["lookup_results"]["sources"]),
                            json_response["geo_info"]["country"]["name"],
                            json_response["geo_info"]["city"]["name"],
                            url_result.format(base64.b64encode(ioc.encode()).decode()))
            )
        elif ioc_type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            url_result = "https://metadefender.opswat.com/results/file/{}/hash/overview"
            

            if json_response['scan_results']['scan_all_result_a'].lower() == "no threat detected":
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Nothing found in MetaDefender database")
            elif json_response['scan_results']['scan_all_result_a'] == "In queue":
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Sample in queue, try again later.")
            elif json_response['scan_results']['scan_all_result_a'] == "Clear":
                mod.display(module,
                            ioc,
                            "FOUND",
                            url_result.format(ioc))
            elif json_response['scan_results']['scan_all_result_a'] == "Infected" or \
                 json_response['scan_results']['scan_all_result_a'] == "Suspicious" or \
                 json_response['scan_results']['scan_all_result_a'] == "File is infected, see description":
                mod.display(module,
                            ioc,
                            "FOUND",
                            "AV {}/{} | {}".format(get_color(json_response['scan_results']['total_detected_avs']), json_response['scan_results']['total_avs'], url_result.format(ioc)))
            else:
                mod.display(module,
                            ioc,
                            "DEBUG",
                            json.dumps(json_response, indent=4))
                mod.display(module,
                            ioc,
                            "ERROR",
                            "MetaDefender json_response was not as expected, API may has been updated.")
    elif response_status == 404:
        mod.display(module,
            ioc,
            "NOT_FOUND",
            "Nothing found in MetaDefender")
    
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MetaDefender response.code_status : %d" % (response_status))
    research_finished(module, ioc)
    return None
