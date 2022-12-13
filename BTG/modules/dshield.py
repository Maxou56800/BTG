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
import xml.etree.ElementTree as ET

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

cfg = Config.get_instance()


class DShield:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search IOC in DShield database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = True
        self.headers = self.config["user_agent"]
        if self.type not in self.types:
            return None
        self.Search()

    def Search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in DShield...")
        
        url = "https://www.dshield.org/api/ip/{}".format(self.ioc)
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
        root = ET.fromstring(response_text)
        total_reports = 0
        honeypot_attacks = 0
        for element in root:
            if element.tag == "count":
                if element.text:
                    total_reports = int(element.text)
            elif element.tag == "attacks":
                if element.text:
                    honeypot_attacks = int(element.text)

        if total_reports == 0 and honeypot_attacks == 0:
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "No reports and no honeypot attacks from this IP address"
            )
            return None
        mod.display(module,
                    ioc,
                    message_type="FOUND",
                    string=" | ".join([
                        "Total reports: {}".format(get_color(total_reports)),
                        "Total honeypot attacks: {}".format(get_color(honeypot_attacks)),
                    ])
        )

        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="DShield connection status : %d" % (response_status))
