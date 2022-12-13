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

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.io import colors

from pycti import OpenCTIApiClient

cfg = Config.get_instance()


class OpenCTI:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "domain", "IPv4",
                      "IPv6", "URL", "SHA256"]
        self.search_method = "Onpremises"
        self.description = "Search IOC in OpenCTI database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verify = self.config['opencti_verifycert']
        self.proxy = self.config['proxy_host']
        
        config_keys = ["opencti_url", "opencti_api_keys", "opencti_verifycert", "opencti_is_online_instance"]
        for key in config_keys:
            if key not in self.config:
                mod.display(self.module_name,
                        self.ioc,
                        "DEBUG",
                        "OpenCTI config keys not found in your configuration file (btg.cfg)")
                self.research_finished()
                return None
        

        if self.config["opencti_is_online_instance"] and self.config["offline"] :
            mod.display(self.module_name,
                        self.ioc,
                        "DEBUG",
                        "OpenCTI search is disabled, because online instance is True and Offline mode is True in config file")
            self.research_finished()
            return None
        length = len(self.config['opencti_url'])
        if length != len(self.config['opencti_api_keys']) and length <= 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "OpenCTI fields in btg.cfg are missfilled, checkout commentaries.")
            self.research_finished()
            return None
        for indice in range(len(self.config['opencti_url'])):
            opencti_url = self.config['opencti_url'][indice].rstrip("/")
            opencti_key = self.config['opencti_api_keys'][indice]
            self.Search(opencti_url, opencti_key, indice)

    def get_tlp_color(self, TLP):
        # str: 'TLP:CLEAR'
        if TLP == "TLP:CLEAR":
            return "{}{}{}{}".format(
                colors.TLP_CLEAR,
                TLP,
                colors.NORMAL,
                colors.BOLD
            )
        elif TLP == "TLP:GREEN":
            return "{}{}{}{}".format(
                colors.TLP_GREEN,
                TLP,
                colors.NORMAL,
                colors.BOLD
            )
        elif TLP == "TLP:AMBER":
            return "{}{}{}{}".format(
                colors.TLP_AMBER,
                TLP,
                colors.NORMAL,
                colors.BOLD
            )
        elif TLP == "TLP:RED":
            return "{}{}{}{}".format(
                    colors.TLP_RED,
                    TLP,
                    colors.NORMAL,
                    colors.BOLD
                )
        # TLP:CLEAR
        return TLP

    def Search(self, opencti_url, opencti_key, indice):
        mod.display(self.module_name, self.ioc, "INFO", "Search in opencti...")

        opencti_api_client = OpenCTIApiClient(opencti_url, opencti_key, log_level="CRITICAL", ssl_verify=self.verify, proxies=self.proxy)
        result = opencti_api_client.stix_cyber_observable.list(search=self.ioc)
        if not len(result):
            mod.display(self.module_name,
                        self.ioc,
                        "NOT_FOUND",
                        "Nothing found in OpenCTI database: {}".format(opencti_url))
            self.research_finished()
            return None
        for observable in result:
            display_url = "{}/dashboard/observations/observables/{}".format(opencti_url, observable["id"])
            #mod.display(self.module_name, self.ioc, "DEBUG", json.dumps(observable, indent=4))
            TLP_display = ""
            if "objectMarking" in observable and len(observable["objectMarking"]):
                if "entity_type" in observable["objectMarking"][0] and observable["objectMarking"][0]["entity_type"] == "Marking-Definition":
                    TLP_display = "{} | ".format(self.get_tlp_color(observable["objectMarking"][0]["definition"]))
            mod.display(self.module_name,
                        self.ioc,
                        "FOUND",
                        "{}Details: {}".format(
                            TLP_display, 
                            display_url
                        )
            )
            # Strange false positive in next loop ..
            self.research_finished()
            return 
        self.research_finished()
        return None

    def research_finished(self):
        mod.display(self.module_name,
                        self.ioc,
                        "FINISHED")
        return
