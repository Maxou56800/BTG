#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Robin Marsollier
# Copyright (c) 2017 Alexandra Toussaint
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

from netaddr import IPAddress, IPNetwork

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod

class Spamhaus:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search IP in SpamHaus feeds"
        self.author = "Robin Marsollier"
        self.creation_date = "20-03-2017"
        self.type = type
        self.ioc = ioc

        self.search()

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "https://www.spamhaus.org/drop/"
        paths = [
            "drop.txt",
            "edrop.txt",
            "dropv6.txt",
        ]
        for path in paths:
            try:
                content = Cache(self.module_name, url, path, self.search_method).content
            except NameError as e:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            e)
                return None
            for line in content.split("\n"):
                try:
                    if line[0] != ';':
                        if IPAddress(self.ioc) in IPNetwork(line.split(" ")[0]):
                            mod.display(self.module_name,
                                        self.ioc,
                                        "FOUND",
                                        "%s%s" % (url, path))
                except:
                    pass

        mod.display(self.module_name,
                    self.ioc,
                    "NOT_FOUND",
                    "Nothing found in SpamHaus feeds")
