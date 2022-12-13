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

cfg = Config.get_instance()


class Mwdb:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "domain", "IPv4",
                      "IPv6", "URL", "SHA256", "SHA512"]
        self.search_method = "Onpremises"
        self.description = "Search IOC in MWDB database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.proxy = self.config['proxy_host']
        self.verify = self.config['mwdb_verifycert']
        if self.config["offline"] and self.config["mwdb_is_online_instance"]:
            mod.display(self.module_name,
                        self.ioc,
                        "DEBUG",
                        "MWDB search is disabled, because online instance is True and Offline mode is True in config file")
            self.research_finished()
            return None
        length = len(self.config['mwdb_api_url'])
        if length != len(self.config['mwdb_api_keys']) and length <= 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "MWDB fields in btg.cfg are missfilled, checkout commentaries.")
            self.research_finished()
            return None
        for indice, mwdb_url in enumerate(self.config['mwdb_api_url']):
            self.headers = {
                'accept': 'application/json',
                "Authorization": "Bearer {}".format(self.config['mwdb_api_keys'][indice])
            }
            mwdb_key = self.config['mwdb_api_keys'][indice]
            self.Search(mwdb_url, mwdb_key, indice)

    def Search(self, mwdb_api_url, mwdb_api_key, indice):
        mod.display(self.module_name, self.ioc, "INFO", "Search in MWDB...")
        if self.type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            search_attribute = self.type.lower()
            search_endpoint = "/api/file"
            url = '{}{}?query={}:{}'.format(mwdb_api_url, search_endpoint, search_attribute, self.ioc)
        elif self.type in ["IPv4", "IPv6", "domain", "URL"]:
            # Search malware CONFIG 
            if self.type == "URL":
                search_query = 'cfg.urls*.url:"{}"'.format(self.ioc)
            else:
                search_query = 'cfg.c2*.host:"*{0}*" OR cfg.urls*.url:"*{0}*"'.format(self.ioc)
            search_endpoint = "/api/config"
            url = '{}{}?query={}'.format(mwdb_api_url, search_endpoint, search_query)

        request = {'url': url,
                'headers': self.headers,
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

def research_finished(module, ioc, message=""):
    mod.display(module,
                    ioc,
                    "FINISHED")
    return

def response_handler(response_text, response_status, module, ioc, ioc_type, server_id):
    web_url = cfg['mwdb_api_url'][server_id]
    if web_url[-1] == "/":
        web_url = web_url[:-1]
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="MWDB json_response was not readable.")
            research_finished(module, ioc)
            return None
        
        if ioc_type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            if len(json_response["files"]) == 0:
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Nothing found in MWDB:%s database" % (web_url))
                research_finished(module, ioc)
                return None
            for file in json_response["files"]:
                tag_to_display = []
                for tag in file["tags"]:
                    tag_to_display.append(tag["tag"])
                mod.display(module,
                    ioc,
                    "FOUND",
                    "{}/file/{} | Tags: {}".format(web_url, file["sha256"], ", ".join(tag_to_display)))
                research_finished(module, ioc)
                return None
        elif ioc_type in ["IPv4", "IPv6", "domain", "URL"]:
            if len(json_response["configs"]) == 0:
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Nothing found in MWDB:%s database" % (web_url))
                research_finished(module, ioc)
                return None
            families = []
            for config in json_response["configs"]:
                if config["family"] not in families:
                    families.append(config["family"])
            if ioc_type == "URL":
                search_url = "{}/configs?q={}".format(
                    web_url,
                    urllib.parse.quote('cfg.urls*.url:"{}"'.format(ioc)))
            else:
                search_url = "{}/configs?q={}".format(
                    web_url,
                    urllib.parse.quote('cfg.c2*.host:"*{0}*" OR cfg.urls*.url:"*{0}*"'.format(ioc)))
            mod.display(module,
                ioc,
                "FOUND",
                "Total {} match: {} (Families: {}) | Search URL: {}".format(
                    ioc_type, 
                    len(json_response["configs"]),
                    ", ".join(families),
                    search_url
                )
            )
            research_finished(module, ioc)
            return None
        else:
            mod.display(module,
                ioc,
                "ERROR",
                "Wrong IOC type: {}".format(json.dumps(json_response, indent=4)))
        research_finished(module, ioc)
        return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MWDB connection status : %d" % (response_status))
    research_finished(module, ioc)
    return None