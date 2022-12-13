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

class Signature_base_neo23x0:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "domain", "MD5", "SHA1", "SHA256"]
        self.search_method = "Cache"
        self.description = "Search an IPv4 in tor exits nodes"
        self.type = type
        self.ioc = ioc

        self.search()

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/"

        if self.type in ["IPv4", "domain"]:
            path = "c2-iocs.txt"
        elif self.type in ["MD5", "SHA1", "SHA256"]:
            path = "hash-iocs.txt"
        else:
            return None
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
                    "Nothing found in Signature-Base feeds")

            return None
        
        if self.type in ["IPv4", "domain"]:
            title = ""
            for line in content.split("\n"):
                if line.strip() == "":
                    continue
                try:
                    line[0]
                except:
                    mod.display(self.module_name, self.ioc, "DEBUG", line)

                if line[0] == "#":
                    title = line.split("#")[1].strip()
                if self.ioc.lower() in line.lower():
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "{}".format(title))
        elif self.type in ["MD5", "SHA1", "SHA256"]:
            for line in content.split("\n"):
                if line.strip() == "" or line[0] == "#":
                    continue
                if self.ioc.lower() in line.lower():
                    title = line.split(";")[1]
                    mod.display(self.module_name,
                        self.ioc,
                        "FOUND",
                        "{}".format(title))
                    
            return None
