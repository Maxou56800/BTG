#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2018 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

from os import chmod, mkdir, makedirs, remove, stat, listdir
from os.path import exists, isdir, join, basename
from requests.exceptions import ConnectionError, ReadTimeout
from time import mktime
import datetime
import requests
import sys
import zipfile
from time import sleep

from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod


class Cache:
    def __init__(self, module_name, url, filename, search_method, is_zip_compressed=False, headers=None):
        self.config = Config.get_instance()
        self.module_name = module_name
        self.url = url
        self.filename = self.new_filename = filename
        self.temp_folder = "%s%s/" % (self.config["temporary_cache_path"], self.module_name)
        self.is_zip_compressed=False
        self.status_code = None
        if not headers:
            self.headers = self.config["user_agent"]
        else:
            self.headers = headers
        position = 0
        filename_copy = self.filename
        if not self.filename.isalnum():
            filename_copy = self.filename.replace("_", "").replace("-", "")
            for pos, char in enumerate(filename_copy):
                if not char.isalnum() and char != '.':
                    position = pos
        self.new_filename = filename_copy[position:]

        if not len(basename(self.new_filename)):
            self.new_filename = "{}_downloaded.raw".format(self.module_name)
        self.temp_file = "%s%s" % (self.temp_folder, self.new_filename)
        self.extracted_folder = None
        if is_zip_compressed:
            self.extracted_folder = join(self.temp_folder, "{}_extracted/".format(self.temp_file)) 

        self.createModuleFolder()
        if self.checkIfNotUpdate():
            if mod.allowedToSearch(search_method) and (not self.config["offline"] or self.config["offline_allow_cache_module_download"]):
                self.downloadFile()
                if self.is_zip_compressed:
                    self.decompress_zip(join(self.temp_folder, self.new_filename))
            else:
                mod.display("{}.cache".format(self.module_name),
                    message_type="INFO",
                    string="Offline parameter is set on, cannot refresh outdated cache")

        self.content = self.getContent()


    def getContent(self):
        files_to_read = []
        if self.extracted_folder:
            # Add extracted files to the list
            if not exists(self.extracted_folder):
                zipfile_path = join(self.temp_folder, self.new_filename)
                if exists(zipfile_path):
                    self.decompress_zip(zipfile_path)
            for filename in listdir(self.extracted_folder):
                files_to_read.append(join(self.extracted_folder, filename))
        else:
            # If not archive append only the downloaded file
            files_to_read.append(self.temp_file)

        file_content = ""
        for file_to_read in files_to_read:
            if exists(file_to_read):
                try:
                    file_content = file_content + open(file_to_read, encoding="ISO-8859-1").read()
                except:
                    file_content = file_content + open(file_to_read).read()
        return file_content.strip()

    def decompress_zip(self, zip_file):
        if not exists(zip_file):
            return None
        sleep(1)
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(self.extracted_folder)

    def downloadFile(self):
        """
            Get file from web
        """
        if self.config["offline"] and not self.config["offline_allow_cache_module_download"]:
            mod.display("{}.cache".format(self.module_name),
                    message_type="ERROR",
                    string="[Kill switch] Racket hole! {}{}".format(self.url, self.filename))
            return
        mod.display("{}.cache".format(self.module_name),
                    message_type="DEBUG",
                    string="Update {}{}".format(self.url, self.filename))
        full_url = "{}{}".format(self.url, self.filename)
        try:
            r = requests.get(
                full_url,
                stream=True, 
                headers=self.headers,
                proxies=self.config["proxy_host"],
                timeout=self.config["requests_timeout"]
            )
        except ConnectionError as e:
            mod.display("{}.cache".format(self.module_name),
                        message_type="ERROR",
                        string=e)
            return
        except ReadTimeout as e:
            mod.display("{}.cache".format(self.module_name),
                        message_type="ERROR",
                        string="Timeout: %s" % (full_url))
            return
        except:
            raise
        self.status_code = r.status_code
        if r.status_code == 200:
            if not exists("%s.lock" % self.temp_file):
                open("{}.lock".format(self.temp_file), 'a').close()
                chmod("{}.lock".format(self.temp_file), 0o666)
                if exists(self.temp_file):
                    to_chmod = False
                else:
                    to_chmod = True
                with open(self.temp_file, 'wb') as f:
                    for chunk in r:
                        f.write(chunk)
                if to_chmod:
                    chmod(self.temp_file, 0o666)
                try:
                    remove("{}.lock".format(self.temp_file))
                except:
                    raise
        elif self.module_name == "malshare" and r.status_code == 404:
            # When we have a 404 from malshare it is a valid negative response
            mod.display("{}.cache".format(self.module_name),
                        message_type="DEBUG",
                        string="Hash not found on malshare, it is alright. Response code: {} | {}".format(r.status_code, full_url))
            return
        elif r.status_code == 503:
            mod.display("{}.cache".format(self.module_name),
                         message_type="ERROR",
                         string="Service Unavailable (%d) | %s" % (r.status_code, full_url))
            return
        else:
            mod.display("{}.cache".format(self.module_name),
                        message_type="ERROR",
                        string="Response code: {} | {}".format(r.status_code, full_url))
            return
    def checkIfNotUpdate(self):
        """
            True: Need to be updated
            False: Nothing to do
        """
        if exists(self.temp_file):
            if not self.compareUpdatedDate():
                return False
        return True

    def compareUpdatedDate(self):
        """
            Compare date now and edited date
        """
        if self.config["temporary_cache_update"] <= 0:
            return False
        date_to_compare = datetime.datetime.now() - datetime.timedelta(seconds=self.config["temporary_cache_update"]*60)
        last_update = stat(self.temp_file).st_mtime
        if last_update < int(mktime(date_to_compare.timetuple())):
            # Need to update
            return True
        # Don't need
        return False

    def createModuleFolder(self):
        if not isdir(self.config["temporary_cache_path"]):
            try:
                makedirs(self.config["temporary_cache_path"])
            except:
                mod.display("{}.cache".format(self.module_name),
                            "FATAL_ERROR",
                            "Unable to create {} directory. (Permission denied)".format(self.config["temporary_cache_path"]))
                sys.exit()
            chmod(self.config["temporary_cache_path"], 0o770)
        if not isdir(self.temp_folder):
            mkdir(self.temp_folder)
            chmod(self.temp_folder, 0o770)
