#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
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

from datetime import datetime
from os import chmod
from os.path import exists
from platform import system
import re
import sys
import redis
import tldextract

from BTG.lib.config_parser import Config
from BTG.lib.redis_config import init_redis
from BTG.lib.utils import cluster, pidfile

class module:
    """
        This class display prettily informations
    """
    def __init__(self):
        return None

    @classmethod
    def display(self, research_module="INIT", ioc="", message_type="DEBUG", string=""):
        config = Config.get_instance()
        pidfile_dir = "/tmp/BTG/data"
        pidfile_path = pidfile.exists_pidfile(pidfile_dir)
        # This cond should always be True otherwise it means,
        # main process died and did not notify us
        if pidfile_path == pidfile_dir:
            sys.exit()
        else:
            lockname, dictname = cluster.get_keys(pidfile_path)

        if ioc != "":
            ioc_display = ioc_formater.clean_ioc(ioc)
            if len(ioc_display) >= 67:
                ioc_display = '%s%s...' % (ioc_display[:64], colors.NORMAL)
            ioc_show = "{%s%s%s} " % (colors.INFO, ioc_display, colors.NORMAL)
        else:
            ioc_show = " "
        current_date = datetime.now().strftime('[%d-%m-%Y %H:%M:%S]')
        display_date = ""
        if "display_log_date" in config and config["display_log_date"]:
            display_date = current_date
        output = "%s[%s%s%s][%s%s%s]%s%s%s%s" % (display_date,
                                               colors.MODULE,
                                               research_module,
                                               colors.NORMAL,
                                               getattr(colors, message_type),
                                               message_type,
                                               colors.NORMAL,
                                               ioc_show,
                                               colors.BOLD,
                                               string,
                                               colors.NORMAL)

        log_folder = config["log_folder"]
        if message_type in ["FOUND", "NOT_FOUND", "ERROR", "WARNING", "INFO", "DEBUG", "FINISHED"]:
            # Logs founds in specific file
            if message_type == "FOUND":
                log_path = log_folder + config["log_found_file"]
                if not exists(log_path):
                    open(log_path, 'a+').close()
                    chmod(log_path, 0o666)
                f = open(log_path, 'a')
                if config["display_log_date"]:
                    # Date already writen in output variable
                    output_line = "{}\n".format(output)
                else:
                    output_line = "{}{}\n".format(current_date, output)
                
                f.write(output_line)
                f.close()
            # Logs errors and warning in specific file
            elif message_type == "ERROR" or message_type == "WARNING":
                log_path = log_folder + config["log_error_file"]
                if not exists(log_path):
                    open(log_path, 'a+').close()
                    chmod(log_path, 0o666)
                f = open(log_path, 'a')
                if config["display_log_date"]:
                    # Date already writen in output variable
                    output_line = "{}\n".format(output)
                else:
                    output_line = "{}{}\n".format(current_date,
                                                    output)
                f.write(output_line)
                f.close()
            
            # Start redis communication
            redis_host, redis_port, redis_password = init_redis()
            conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                     password=redis_password)
            message = {
                'type': message_type,
                'ioc': ioc,
                'string': output
            }
            c = cluster.edit_cluster(ioc, research_module, message,
                                     conn, lockname, dictname)
            if "display_group_by_ioc" in config and config["display_group_by_ioc"]:
                if c:
                    cluster.print_cluster(c, conn)
                return None
            if message_type == "NOT_FOUND" and not config["display_not_found"]:
                return None
            elif message_type == "WARNING" and not config["display_warnings"]:
                return None
            elif message_type == "ERROR" and not config["display_errors"]:
                return None
            elif message_type in ["INFO", "FINISHED"] and not config["display_info"]:
                return None
            elif message_type == "DEBUG" and not config["debug"]:
                return None
            print(output)
            return None

        elif message_type == "FATAL_ERROR":
            log_path = log_folder + config["log_error_file"]
            if not exists(log_path):
                open(log_path, 'a+').close()
                chmod(log_path, 0o666)
            f = open(log_path, 'a')
            f.write("%s%s\n" % (datetime.now().strftime('[%d-%m-%Y %H:%M:%S]'), output))
            f.close()
            print(output)
            return None

    @classmethod
    def allowedToSearch(self, status, module=""):
        config = Config.get_instance()
        """
            Input: "Online", "Onpremises"
        """
        if status == "Onpremises":
            '''
            here the module claims to be related to an on premises service
            , i.e. being inside researcher network, so we allow the lookup

            modules: misp, cuckoosandbox, mwdb, viper
            '''
            if config["offline"]:
                if module == "misp" and config["misp_is_online_instance"]:
                    return False
                elif module == "cuckoosandbox" and config["cuckoosandbox_is_online_instance"]:
                    return False
                elif module == "mwdb" and config["mwdb_is_online_instance"]:
                    return False
                elif module == "viper" and config["viper_is_online_instance"]:
                    return False
                elif module == "opencti" and config["opencti_is_online_instance"]:
                    return False
            return True
        elif status == "Online" and not config["offline"]:
            '''
            the module claims to be online,
            and the user did not set on "offline" configuration,
            so the module can perform his lookup
            '''
            return True
        elif status == "Cache":
            '''
            the module claims to be online,
            but it can store previous research in cache,
            if the cache is up to date,
            it can perform his request even if "offline"
            '''
            return True
        '''
        if none of previous case, lookup forbidden
        '''
        return False

        '''
        possible refactoring :
        if config[offline]:
            if status = onpremises
                truecolorize
            if status = cache
                true
            if status = online
                false
        else:
            true
        '''


class errors:
    """
        This function display prettily errors
    """
    def __init__(self):
        return None

    @classmethod
    def display(self, dict_list=[]):
        if not dict_list:
            return None
        else:
            config = Config.get_instance()
            error_encountered = False
            outputs = []
            for dict in dict_list:
                if dict['nb_error'] > 1:
                    output = "[%s%s%s] encountered %s%d%s errors" % (colors.MODULE,
                                                                     dict['module_name'],
                                                                     colors.NORMAL,
                                                                     colors.NB_ERROR,
                                                                     dict['nb_error'],
                                                                     colors.NORMAL)
                    outputs.append(output)
                    error_encountered = True
                elif dict['nb_error'] == 1:
                    output = "[%s%s%s] encountered %s%d%s error" % (colors.MODULE,
                                                                    dict['module_name'],
                                                                    colors.NORMAL,
                                                                    colors.NB_ERROR,
                                                                    dict['nb_error'],
                                                                    colors.NORMAL)
                    outputs.append(output)
                    error_encountered = True
            if error_encountered:
                log_error_path = config["log_folder"] + config["log_error_file"]
                print("\n--- ERRORS ---")
                for output in outputs:
                    print(output)
                print("\nSee %s for detailed errors" % (log_error_path))


class logSearch:
    def __init__(self, args):
        config = Config.get_instance()
        log_folder = config["log_folder"]
        log_path = log_folder + config["log_search_file"]
        if not exists(log_path):
            open(log_path, 'a').close()
            chmod(log_path, 0o666)
        f = open(log_path, 'a')
        if args.file == "False":
            for ioc in args.observables:
                f.write("%s %s\n" % (datetime.now().strftime('[%d-%m-%Y %H:%M:%S]'), ioc))
            f.close()
        else:
            for file in args.observables:
                with open(file, "r") as f2:
                    for ioc in f2.readlines():
                        f.write("%s %s\n" % (datetime.now().strftime('[%d-%m-%Y %H:%M:%S]'), ioc.strip('\n')))
            f.close()


class colors:
    config = Config.get_instance()
    if system() == "Windows" or config["terminal_color"] is False:
        DEBUG = ''
        INFO = ''
        FINISHED = ''
        FOUND = ''
        WARNING = ''
        ERROR = ''
        FATAL_ERROR = ''
        NORMAL = ''
        BOLD = ''
        MODULE = ''
        NB_ERROR = ''
    else:
        TLP_CLEAR = '\033[0m'          # NOCOLOR
        DEBUG = '\033[38;5;13m'        # LIGHT_MAGENTA
        INFO = '\033[38;5;117m'        # LIGHT_BLUE
        FINISHED = '\033[38;5;117m'    # LIGHT_BLUE
        FOUND = '\033[38;5;10m'        # GREEN
        GOOD = '\033[38;5;10m'         # GREEN
        TLP_GREEN = '\033[38;5;10m'    # GREEN
        NOT_FOUND = '\033[38;5;11m'    # YELLOW
        WARNING = '\033[38;5;11m'      # YELLOW
        LOW_RISK = '\033[38;5;11m'     # YELLOW
        ERROR = '\033[38;5;202m'       # ORANGE
        MEDIUM_RISK = '\033[38;5;202m' # ORANGE
        TLP_AMBER = '\033[38;5;202m'   # ORANGE
        SUSPICIOUS = '\033[38;5;202m' # ORANGE
        FATAL_ERROR = '\033[38;5;9m'   # RED
        INFECTED = '\033[38;5;9m'      # RED
        HIGH_RISK = '\033[38;5;9m'     # RED
        TLP_RED = '\033[38;5;9m'       # RED
        NORMAL = '\033[0m'             # NOCOLOR
        BOLD = '\033[1m'               # BOLD
        MODULE = '\033[38;5;199m'      # PURPLE
        NB_ERROR = '\033[38;5;9m'      # RED
        

class ioc_formater:

    def __init__(self):
        return None

    @classmethod
    def clean_ioc(self, ioc):
        try:
            # Try to clean '.' in domain
            extracted = tldextract.extract(ioc)
            orig = extracted.fqdn
            new = extracted.fqdn.replace(".", "[.]")
            ioc = ioc.replace(orig, new) 
        except:
            pass
        protocole_occurences = re.findall("^[hH][tT][tT][pP]", ioc)
        if len(protocole_occurences):
            protocole_occurences
            ioc = ioc.replace(protocole_occurences[0], "hxxp")    
        return ioc