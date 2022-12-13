#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Robin Marsollier
# Copyright (c) 2017 Alexandra Toussaint
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

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod

cfg = Config.get_instance()


class Misp:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "domain", "IPv4",
                      "IPv6", "URL", "SHA256", "SHA512"]
        self.search_method = "Onpremises"
        self.description = "Search IOC in MISP database"
        self.author = "Conix"
        self.creation_date = "07-10-2016"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.proxy = self.config['proxy_host']
        self.verify = self.config['misp_verifycert']
        if self.config["offline"] and self.config["misp_is_online_instance"]:
            mod.display(self.module_name,
                        self.ioc,
                        "DEBUG",
                        "MISP search is disabled, because online instance is True and Offline mode is True in config file")
            return None
        length = len(self.config['misp_url'])
        if length != len(self.config['misp_key']) and length <= 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "MISP fields in btg.cfg are missfilled, checkout commentaries.")
            return None
        # Add tail slashe to MISP URLs
        self.config['misp_url'] = [u if u.endswith('/') else u + '/' for u in self.config['misp_url']]
        for indice in range(len(self.config['misp_url'])):
            misp_url = self.config['misp_url'][indice]
            misp_key = self.config['misp_key'][indice]
            self.Search(misp_url, misp_key, indice)

    def Search(self, misp_url, misp_key, indice):
        mod.display(self.module_name, self.ioc, "INFO", "Search in misp...")

        url = '{}attributes/restSearch'.format(misp_url)
        self.headers['Authorization'] = misp_key

        payload = {
            'value': self.ioc, 
            'searchall': 1
        }
        data = json.dumps(payload)

        request = {
            'url': url,
            'headers': self.headers,
            'data': data,
            'module': self.module_name,
            'ioc': self.ioc,
            'ioc_type': self.type,
            'verbose': self.verbose,
            'proxy': self.proxy,
            'verify': self.verify,
            'server_id': indice
        }
        json_request = json.dumps(request)
        store_request(self.queues, json_request)


def response_handler(response_text, response_status, module, ioc, ioc_type, server_id):
    web_url = cfg['misp_url'][server_id]
    if not web_url.endswith("/"):
        web_url = "{}/".format(web_url)
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="MISP json_response was not readable.")
            return None

        if "Attribute" in json_response["response"]:
            displayed = []
            for attr in json_response["response"]["Attribute"]:
                event_id = attr["event_id"]
                if event_id not in displayed:
                    event_title = ""
                    if "Event" in attr and "info" in attr["Event"]:
                        event_title = "Event title: {} | ".format(attr["Event"]["info"])
                    mod.display(module,
                                ioc,
                                "FOUND",
                                "{}Event details: {}events/view/{}".format(event_title, web_url,
                                                                event_id))
                    displayed.append(event_id)
                    return None
            mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "Nothing found in MISP:{} database".format(web_url))
            return None
    elif response_status == 429:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MISP instance '{}' received too many requests (Response code: {}).".format(web_url, response_status))
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MISP instance '{}' connection status : {}".format(web_url, response_status))
