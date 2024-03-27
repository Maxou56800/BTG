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

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod
import json

class TweetFeed:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4", "domain", "URL", "MD5", "SHA256"]
        self.search_method = "Online"
        self.description = "Search IOC in TweetFeed"
        self.author = "Maxou56800"
        self.creation_date = "27-03-2024"
        self.type = type
        self.ioc = ioc

        self.search()

    def research_finished(self):
        mod.display(self.module_name,
                        self.ioc,
                        "FINISHED")
        return

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "https://api.tweetfeed.live"
        paths = [
            "/v1/year"
        ]
        for path in paths:
            try:
                req = Cache(self.module_name, url, path, self.search_method)
                content = req.content
            except NameError as e:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            e)
                self.research_finished()
                return None

            try:
                json_content = json.loads(content)
            except:
                mod.display(self.module_name,
                    self.ioc,
                    "ERROR",
                    "Unable to parse Json from TweetFeed")
                return None

            # domain type set
            feed_type = self.type
            if self.type == "IPv4":
                feed_type = "ip"
            elif self.type in ["MD5", "SHA256", "URL"]:
                feed_type = self.type.lower()
            for event in json_content:
                if event["type"] != feed_type:
                    continue
                if self.ioc == event["value"]:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                f"{', '.join(event['tags'])} | {event['user']}: {event['tweet']}")
                    self.research_finished()
                    return None
        mod.display(self.module_name,
                    self.ioc,
                    "NOT_FOUND",
                    "Nothing found in TweedFeed")
        self.research_finished()
        return None