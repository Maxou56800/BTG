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

class Blocklistde:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["IPv4"]
        self.search_method = "Cache"
        self.description = "Search an Blocklist.de blacklist"
        self.type = type
        self.ioc = ioc

        self.search()

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "https://lists.blocklist.de/lists/"
        paths = {
            "strongips.txt": "This IP have been reported and older then 2 month and have more than 5 000 attacks",
            "bruteforcelogin.txt": "This IP have been reported within last 48 hours as having run bruteforce (Web-Logins)",
            "ssh.txt": "This IP have been reported within last 48 hours as having run attacks on SSH services",
            "apache.txt": "This IP have been reported within last 48 hours as having run attacks on HTTP (RFI/DDOS...) services",
            "imap.txt": "This IP have been reported within last 48 hours as having run attacks on IPAM/SASL/POP3 services",
            "ftp.txt": "This IP have been reported within last 48 hours as having run attacks on FTP services",
            "sip.txt": "This IP have been reported within last 48 hours as having run attacks on SIP/VOIP/Asterisk services",
            "bots.txt": "This IP have been reported within last 48 hours as having run bots actions (Example: RFI, SPAM...)",
            "ircbot.txt": "This IP have been reported as having run IRC bot",
            "mail.txt": "This IP have been reported within last 48 hours as having run attacks on Mail, Postfix (SMTP) services",
        }
        found = False
        for path in paths:
            try:
                content = Cache(self.module_name, url, path, self.search_method).content
            except NameError as e:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            e)
                return None
            if self.ioc in content:
                found = True
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "{} | Feed: {}{}".format(paths[path], url, path))
                continue
        if not found:
            mod.display(self.module_name,
                        self.ioc,
                        "NOT_FOUND",
                        "Nothing found in Blocklist.de feeds")
        return None