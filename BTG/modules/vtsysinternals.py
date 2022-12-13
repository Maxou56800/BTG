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
import random
import datetime
import string

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod
from BTG.lib.io import colors

classic_system = [
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-25 18:13:16",
        "hash": "D2DACC822970FF51C1567D7E3B06FCB7CC38272F",
        "image_path": "Z:\\Tools\\procexp64.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:29:49",
        "hash": "183E877F488F2DF9F304F60A42514A334720399F",
        "image_path": "C:\\Windows\\System32\\smartscreen.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-01 18:33:17",
        "hash": "DDA2DF4674CFAC53C721366914D7CD6F8A4A84DA",
        "image_path": "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:25:06",
        "hash": "D9EB054077AB2C75FA2119E6351A290456A7C6A1",
        "image_path": "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2019-12-07 16:54:23",
        "hash": "7AB8040343B1255F8BD765D2FCB78F834FA00C5C",
        "image_path": "C:\\Program Files\\WindowsApps\\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\\SkypeApp.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:24:15",
        "hash": "BA93B6F897778B91DB9D179E14C352AF82210061",
        "image_path": "C:\\Windows\\System32\\conhost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:11",
        "hash": "F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D",
        "image_path": "C:\\Windows\\System32\\cmd.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-02 19:27:01",
        "hash": "BD510B22613BE5D95E9B71D07FF53A846178EF75",
        "image_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2201.10-0\\NisSrv.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2019-12-07 16:57:34",
        "hash": "F0A1C19653ED9E9DB91C8ED73D9D8BF77E4AFC21",
        "image_path": "C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe\\Microsoft.Photos.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-02 11:54:53",
        "hash": "D3DC46078A137F17C50887FF6F17BE40DAB20626",
        "image_path": "C:\\Users\\penombre\\Desktop\\Tools\\SysinternalsSuite\\procexp64.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-02 19:31:54",
        "hash": "3742F26D3D266D015836F22F5B083D7776EF5E0C",
        "image_path": "C:\\Users\\penombre\\Desktop\\Tools\\ida75sp\\ida64.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:23",
        "hash": "2CE12A317BEBF8293F3544433A55D972A5967996",
        "image_path": "C:\\Windows\\System32\\dllhost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:25:05",
        "hash": "AA60D00CD83EC786CAF2191DA000F5EB4EB60C77",
        "image_path": "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:37",
        "hash": "75AD2103EEA3DCF8BFFA3C88E7CFF9AD57E432D0",
        "image_path": "C:\\Windows\\System32\\oobe\\UserOOBEBroker.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:29:40",
        "hash": "424D3FDB3BDC249926E828286C87DE486546BF73",
        "image_path": "C:\\Windows\\System32\\SystemSettingsBroker.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2019-12-07 16:54:41",
        "hash": "4EFE9343CEFCD06CA2667DA20BDD963EBB4C5A9B",
        "image_path": "C:\\Program Files\\WindowsApps\\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\\WinStore.App.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:25:01",
        "hash": "5C15EB26989B7E3BC04D343AE926FD668636B630",
        "image_path": "C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:31:06",
        "hash": "9B39F815CA4416BFF574D01C90D03D2DF2A0BDD7",
        "image_path": "C:\\Windows\\System32\\SgrmBroker.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-02-25 23:14:20",
        "hash": "EDD8F78977EC8A74DAD6E17BB68E824077C07578",
        "image_path": "C:\\Users\\penombre\\Desktop\\Tools\\x64dbg\\release\\x64\\x64dbg.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:16",
        "hash": "F79FC9E0AB066CAD530B949C2153C532A5223156",
        "image_path": "C:\\Windows\\System32\\ApplicationFrameHost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-01 18:23:58",
        "hash": "A39F6B22FD5901B3D04A9B9953027DF8BB2ADFD1",
        "image_path": "C:\\Users\\penombre\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-01-13 13:16:48",
        "hash": "D91127440EBFE8F59CF50357BA5A3F6F091958EE",
        "image_path": "C:\\Windows\\System32\\VBoxTray.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:24:15",
        "hash": "E517743DF665466806596A4C63C512B406EDE7F6",
        "image_path": "C:\\Windows\\System32\\SecurityHealthService.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2019-12-07 11:08:41",
        "hash": "D79D21F4D6741F83FB98FDCF8D06FE8C5D78A799",
        "image_path": "C:\\Windows\\System32\\SecurityHealthSystray.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2019-12-07 16:54:23",
        "hash": "A6CF5E455D2704276ED7331DFE1F7E580EA8794E",
        "image_path": "C:\\Program Files\\WindowsApps\\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\\SkypeBackgroundHost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:25:06",
        "hash": "5DD55FBDF83E3C646DBE744E8A64FA361725817C",
        "image_path": "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:29:50",
        "hash": "AB8539EF6B2A93FF9589DEC4B34A0257B6296C92",
        "image_path": "C:\\Windows\\System32\\RuntimeBroker.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:24:09",
        "hash": "1F4B2B8376FF1A4D307B2B349AAEE42A4D90F8D4",
        "image_path": "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:24:03",
        "hash": "DA6F5F760EA057D382A47D4AC7F25D4C1BBFCFF7",
        "image_path": "C:\\Windows\\System32\\SearchIndexer.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:23:50",
        "hash": "54B1C42B69DDD43C32529B13CDEB210C940E744F",
        "image_path": "C:\\Windows\\explorer.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:24:25",
        "hash": "3175A68FE10C2FD14BEBA8004D9D2243DE8B393D",
        "image_path": "C:\\Windows\\System32\\taskhostw.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:07",
        "hash": "5310BA14A05256E4D93E0B04338F53B4E1D680CB",
        "image_path": "C:\\Windows\\System32\\sihost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-03-02 19:27:01",
        "hash": "26DB4A9BEEF6A6279667B5DDA6ECAACB62D6C9D1",
        "image_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2201.10-0\\MsMpEng.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:17:56",
        "hash": "0A552A20A11A020CACEDB586751F591782D9CE0C",
        "image_path": "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-04-01 10:23:49",
        "hash": "715805A44AE6CB3AC7BC52FB916641159AA62D17",
        "image_path": "C:\\Windows\\System32\\spoolsv.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2022-01-13 21:14:34",
        "hash": "2DFD49110E21477DFAAC11154E7995C34D5711C2",
        "image_path": "C:\\Windows\\System32\\VBoxService.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:23",
        "hash": "010DB07461E45B41C886192DF6FD425BA8D42D82",
        "image_path": "C:\\Windows\\System32\\svchost.exe"
    },
    {
        "autostart_entry": "",
        "autostart_location": "",
        "creation_datetime": "2021-10-06 15:30:26",
        "hash": "67DF2226998590E92CBB3284662EC055638A3C1E",
        "image_path": "C:\\Windows\\System32\\lsass.exe"
    }
]


class VTSysinternals:
    """
        This module allow you to search SHA256 in Virustotal
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["SHA256", "SHA1"]
        self.search_method = "Online"
        self.description = "Search SHA256 IOC in VirusTotal database"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        self.headers = {
            "User-Agent": "VirusTotal",
            "Content-Type": "application/json",
            "Connection": "Keep-Alive", 
            "Accept-Encoding": "None"
        }
        self.proxy = self.config["proxy_host"]
        self.search()

    def search(self):
        mod.display(self.module_name, self.ioc, "INFO", "Search in VirusTotal ...")
        request = self.searchHash()
        store_request(self.queues, request)

    def searchHash(self):
        self.url = "https://www.virustotal.com/partners/sysinternals/file-reports?apikey=4e3202fdbe953d628f650229af5b3eb49cd46b2d3bfe5546ae3c5fa48b554e0c"
        items = classic_system
        fuudate = (datetime.datetime.now()-datetime.timedelta(minutes=(random.randint(1,90)))).strftime("%Y-%m-%d %H:%M:%S")
        items.insert(0, {
            "autostart_entry": "",
            "autostart_location": "",
            "creation_datetime": fuudate,
            "hash": self.ioc.upper(),
            "image_path": "C:\\Windows\\{}.exe".format(''.join(random.choice(string.ascii_lowercase) for i in range(10))),    
        })
        parameters = json.dumps(items)
        request = {
            "url": self.url,
            "headers": self.headers,
            "data": parameters,
            "module": self.module_name,
            "ioc": self.ioc,
            "ioc_type": self.type,
            "verbose": self.verbose,
            "proxy": self.proxy
        }
        json_request = json.dumps(request)
        return json_request

def get_color(positives):
    if positives == 0:
        return "{}{}{}{}".format(
            colors.GOOD,
            positives,
            colors.NORMAL,
            colors.BOLD
        )
    return "{}{}{}{}".format(
            colors.INFECTED,
            positives,
            colors.NORMAL,
            colors.BOLD
        )

def research_finished(module, ioc, message=""):
    mod.display(module,
                    ioc,
                    "FINISHED")
    return

def response_handler(response_text, response_status,
                     module, ioc, ioc_type, server_id=None):
    # Prepare whitelist
    whitelisted_hash = []
    for element in classic_system:
        whitelisted_hash.append(element["hash"])

    if response_status == 200:

        try:
            json_content = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "VirusTotal json_response was not readable.")
            research_finished(module, ioc)
            return None

        found = False
        for data in json_content["data"]:
            if data["hash"] in whitelisted_hash:
                continue
            if data["found"]:
                mod.display(module,
                        ioc,
                        "FOUND",
                        "Score: {}/{} | {}".format(get_color(data["positives"]),
                                               data["total"],
                                               data["permalink"])
                                            )
                found = True  
        if not found:
            mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "Nothing found in Virustotal")
    else:
        mod.display(module,
                    ioc,
                    "ERROR",
                    "VirusTotal response.code_status : %d" % (response_status))
    research_finished(module, ioc)
    return None