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

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod


class feodotracker():
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "domain"]
        self.search_method = "Online"
        self.description = "Search IOC in FeodoTracker database"
        self.author = "Conix"
        self.creation_date = "31-05-2018"
        self.type = type
        self.ioc = ioc

        self.search()

    def search(self):
        mod.display(self.module_name, "", "INFO", "Search in FeodoTracker ...")
        url = "https://feodotracker.abuse.ch/blocklist/?download="
        paths = [
            "ipblocklist",
            "domainblocklist"
        ]

        if self.type == "IPv4":
            path = paths[0]
        elif self.type == "domain":
            path = paths[1]
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "This IOC is of an unrecognized type: %s" % (self.type))
        try:
            content = Cache(self.module_name, url, path, self.search_method).content
        except NameError as e:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        e)
            return None
        if content.find(self.ioc) == -1:
            mod.display(self.module_name,
                        self.ioc,
                        "NOT_FOUND",
                        "Nothing found in FeodoTracker")
            return None
        else:
            url_reponse = "https://feodotracker.abuse.ch/host/"+self.ioc
            mod.display(self.module_name,
                        self.ioc,
                        "FOUND",
                        url_reponse)
            return None
