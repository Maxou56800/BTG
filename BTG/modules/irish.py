#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Lancelot Bogard
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
from BTG.lib.io import module as mod


class Irish():
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA256", "SHA1"]
        self.search_method = "Online"
        self.description = "Search IOC in IRIS-H. database"
        self.author = "Conix"
        self.creation_date = "01-12-2017"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        self.search()

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        self.url = "https://iris-h.services/api/v2/search?hash=" + self.ioc

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


def response_handler(response_text, response_status, module,
                     ioc, ioc_type, server_id=None):
    if response_status == 200:
        try:
            json_content = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="Irish json_response was not readable.")
            return None
        if "You have to try harder!" in json_content:
            mod.display(module,
                ioc,
                "NOT_FOUND",
                "Nothing found in irsih DB"
            )
            return None
        mod.display(module,
                    ioc,
                    "FOUND",
                    "URL: https://iris-h.services/pages/report/%s" % (ioc))
        return None
    elif response_status == 404:
        mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "Nothing found in irsih DB")
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="Irish connection status : %d" % (response_status))
        return None
