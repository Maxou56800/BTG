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

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod
from BTG.lib.io import colors

import tldextract
import re

class PhishTank:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL", "domain", "IPv4"]
        self.search_method = "Cache"
        self.description = "Search an PhishTank database"
        self.type = type
        self.ioc = ioc
        self.headers = self.config["user_agent"]
        self.api_key = None
        if "phishtank_optional_username" in self.config and self.config["phishtank_optional_username"]:
            self.headers["User-Agent"] = "phishtank/{}".format(self.config["phishtank_optional_username"])
        if "phishtank_optional_api_key" in self.config and self.config["phishtank_optional_api_key"]:
            self.api_key = self.config["phishtank_optional_api_key"]
        if self.type == "domain" and "phishtank_disable_domain_search" in self.config and self.config["phishtank_disable_domain_search"]:
            return None
        self.search()

    def research_finished(self):
        mod.display(self.module_name,
                        self.ioc,
                        "FINISHED")
        return

    def clean_ioc(self, ioc):
        extracted = tldextract.extract(ioc)
        orig = ".".join(extracted)
        new = "[.]".join(extracted)
        ioc = ioc.replace(orig, new) 
        protocole_occurences = re.findall("^[hH][tT][tT][pP]", ioc)
        if len(protocole_occurences):
            protocole_occurences
            ioc = ioc.replace(protocole_occurences[0], "hxxp")    
        return ioc

    def get_color(self, ioc):
        return "{}{}{}{}".format(
                colors.INFECTED,
                ioc,
                colors.NORMAL,
                colors.BOLD
        )

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Searching...")
        if self.api_key:
            route = "/data/{}/".format(self.api_key)
        else:
            route = "/data/"
        url = "http://data.phishtank.com{}".format(route)
        paths = {
            "online-valid.csv"
        }
        found = False
        for path in paths:
            try:
                content = Cache(self.module_name, url, path, self.search_method, headers=self.headers).content
            except NameError as e:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            e)
                self.research_finished()
                return None
            if not content.find(self.ioc):
                continue
            
            for line in content.strip().split("\n"):
                if line.find(self.ioc) == -1:
                    continue
                
                line_splited = line.split(",")
                if self.type == "URL" and "phishtank_exact_url" in self.config and self.config["phishtank_exact_url"]:
                    if line_splited[1] != self.ioc:
                        continue
                    output_found = "Pishing type: {} | Phishing details: {}".format(line_splited[-1], line_splited[2])
                else:
                    output_found = "Malicious URL: {} | Pishing type: {} | Phishing details: {}".format(self.get_color(self.clean_ioc(line_splited[1])), line_splited[-1], line_splited[2])
                
                found = True
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            output_found)
        if not found:
            mod.display(self.module_name,
                        self.ioc,
                        "NOT_FOUND",
                        "Nothing found in PhishTank feeds")
        self.research_finished()
        return None