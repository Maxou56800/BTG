#!/usr/bin/python
# -*- coding: utf-8 -*-
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

import csv
import requests
import re

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod

class Vxvaultquery():
    """
        This module performs a crawling for VXVault.net
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "IPv4"]
        self.search_method = "Online"
        self.description = "Search IOC in VXVault db using query"
        self.creation_date = "09-12-2022"
        self.type = type
        self.ioc = ioc

        self.search()

    def research_finished(self):
        mod.display(self.module_name,
                        self.ioc,
                        "FINISHED")
        return

    def search(self):
        mod.display(self.module_name,
                    self.ioc,
                    "INFO",
                    "Search in VXVault with queries ...")
        self.webpage_crawling()
        self.research_finished()


    def webpage_crawling(self):
        url = "http://vxvault.net/ViriList.php"

        if self.type == "MD5":
            url_variable = "?MD5="
        elif self.type == "IPv4":
            url_variable = "?IP="

        response = requests.get(url+url_variable+self.ioc)
        if response.status_code == 200:
            if self.type == "IPv4":
                if re.match("<TD class=fonce><a  href='ViriList.php\?IP=.+'>.+<\/a>", response.text):
                    mod.display(self.module_name,
                        self.ioc,
                        "FOUND",
                        url+url_variable+self.ioc)
                else:
                    mod.display(self.module_name,
                                self.ioc,
                                "NOT_FOUND",
                                "Nothing found in VXVault")
                    return None
                return None
            if self.type == "MD5":
                if response.text.find(self.ioc.upper()) == -1:
                    mod.display(self.module_name,
                                self.ioc,
                                "NOT_FOUND",
                                "Nothing found in VXVault")
                    return None
                else:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                url+url_variable+self.ioc)
                    return None
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "MalwareConfig API connection status %d" % response.status_code)
            return None


