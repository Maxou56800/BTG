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

import csv

from BTG.lib.io import module as mod
from BTG.lib.cache import Cache


class threatfox():
    """
        URLhaus IOC module
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["URL", "domain", "IPv4", "MD5", "SHA256"]
        self.search_method = "Online"
        self.description = "Search IOC in THREAT fox database"
        self.author = "Maxou56800"
        self.creation_date = "12-08-2022"
        self.type = type
        self.ioc = ioc

        self.search()

    def search(self):
        mod.display(self.module_name, "", "INFO", "Search in THREAT fox ...")
        url = "https://threatfox.abuse.ch"
        paths = [
            "/export/csv/full/"
        ]
        try:
            content = Cache(self.module_name, url, paths[0], self.search_method, is_zip_compressed=True).content
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
                        "Nothing found in URLhause")
            return None
        else:
            try:
                reader = csv.reader(content.split('\n'), delimiter=',')
            except:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Could not parse CSV feed")
                return None
            for row in reader:
                if row[0][0] == "#":
                    continue
                if self.ioc in row[2]:
                    remote_ioc_type = row[4].replace('"', "").strip()
                    if remote_ioc_type == "payload":
                        mod.display(self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "https://threatfox.abuse.ch/ioc/{}/ - Malware ID: {} - Tags: {}".format(
                                        row[1].replace('"', "").strip(),
                                        row[5].replace('"', "").strip(),
                                        row[7].replace('"', "").replace("'", "").strip()
                                    )
                        )
                    elif remote_ioc_type == "botnet_cc":
                        mod.display(self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "https://threatfox.abuse.ch/ioc/{}/ - Malware ID: {} - Tags: {}".format(
                                        row[1].replace('"', "").strip(),
                                        row[5].replace('"', "").strip(),
                                        row[11].replace('"', "").strip()
                                    )
                        )
                    else:
                        mod.display(self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "https://threatfox.abuse.ch/ioc/{}/ - Check link for more information".format(
                                        row[1].replace('"', "").strip(),
                                        row[5].replace('"', "").strip(),
                                        row[11].replace('"', "").strip()
                                    )
                        )
                    return None
