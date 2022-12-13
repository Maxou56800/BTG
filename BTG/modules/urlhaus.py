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

import csv

from BTG.lib.io import module as mod
from BTG.lib.cache import Cache


class urlhaus():
    """
        URLhaus IOC module
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL", "domain", "IPv4"]
        self.search_method = "Online"
        self.description = "Search IOC in URLhaus database"
        self.author = "Conix"
        self.creation_date = "31-05-2018"
        self.type = type
        self.ioc = ioc

        self.search()

    def research_finished(self):
        mod.display(self.module_name,
                        self.ioc,
                        "FINISHED")
        return

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in URLhaus ...")
        url = "https://urlhaus.abuse.ch/downloads/"
        paths = [
            "/downloads/csv/"
        ]
        try:
            content = Cache(self.module_name, url, paths[0], self.search_method, is_zip_compressed=True).content
        except NameError as e:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        e)
            self.research_finished()
            return None
        if content.find(self.ioc) == -1:
            mod.display(self.module_name,
                        self.ioc,
                        "NOT_FOUND",
                        "Nothing found in URLhaus")
            self.research_finished()
            return None
        else:
            try:
                reader = csv.reader(content.split('\n'), delimiter=',')
            except:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Could not parse CSV feed")
                self.research_finished()
                return None
            for row in reader:
                if row[0][0] == "#":
                    continue
                if self.ioc in row[2]:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "{} - C2 status: {} - Tags: {}".format(row[7], row[3], row[6]))
                    #return None
        self.research_finished()
        return None