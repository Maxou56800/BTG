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

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

cfg = Config.get_instance()


class urlscan:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL"]
        self.search_method = "Online"
        self.description = "Search IOC in urlscan database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = True
        self.headers = self.config["user_agent"]

        self.Search()

    def Search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in urlscan...")
        url = 'https://urlscan.io/api/v1/search/?q=task.url:"{}"'.format(self.ioc.replace('"', "%22").replace("\\", "%5c"))
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
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="urlscan json_response was not readable.")
            return None
        if json_response["total"] == 0:
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "This addresse IP seem to be clean for urlscan")
            return None
        search_url = 'https://urlscan.io/search/#{}'.format(urllib.parse.quote('task.url:"'+ioc+'"'))
        nb_elements = len(json_response["results"])
        all_tags = []
        for element in json_response["results"]:
            if "tags" in element["task"]:
                for tag in element["task"]["tags"]:
                    all_tags.append(tag)
        if len(all_tags) == 0:
            mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "No tags attribute, you need to check manualy | Search URL: {}".format(search_url))
            return None
        mod.display(module,
                    ioc,
                    "FOUND",
                    "Tags: {} | Search URL: {}".format(", ".join(all_tags), search_url)
        )
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="urlscan connection status : %d" % (response_status))
