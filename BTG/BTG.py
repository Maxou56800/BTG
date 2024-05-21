#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2018 Conix Cybersecurity
# Copyright (c) 2016-2017 Lancelot Bogard
# Copyright (c) 2016-2017 Robin Marsollier
# Copyright (c) 2017 Alexandra Toussaint
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

from base64 import b64decode
from datetime import datetime
from os import listdir, path, remove, setsid, getpid, chmod, makedirs
from os.path import isfile, join, exists, isdir, dirname
from redis import Redis
from rq import Connection, Queue
from string import Formatter
import argparse
import csv
import re
import redis
import socket
import subprocess
import sys
import time
import tldextract
import validators
import ipaddress
import json

from BTG.lib.config_parser import Config
from BTG.lib.io import colors
from BTG.lib.io import errors as err
from BTG.lib.io import logSearch
from BTG.lib.io import module as mod
from BTG.lib.redis_config import init_redis, init_variables, number_of_worker
from BTG.lib.utils import cluster, pidfile, redis_utils
from BTG.lib.worker_tasks import module_worker_request

config = Config.get_instance()
version = "2.5"     # BTG version


class BTG():
    """
        BTG Main class
    """
    def __init__(self, args, modules):
        redis_host, redis_port, redis_password = init_redis()
        try:
            conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                     password=redis_password)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Cannot establish connection with Redis")
            sys.exit()

        global observable_list
        queues = [working_queue, request_queue]

        if args.file == "False":
            observable_list = args.observables
        else:
            observable_list = []
            for file in args.observables:
                with open(file, "r") as f1:
                    try:
                        observable_list = list(set(observable_list +
                                                   f1.read().strip().splitlines()))
                    except:
                        mod.display("MAIN",
                                    message_type="FATAL_ERROR",
                                    string="Something went wrong with the argument file")
                    finally:
                        f1.close()

        for argument in observable_list:
            type = self.checkType(argument.lower())
            if type in ["IPv4", "IPv6"] and ipaddress.ip_address(argument).is_private:
                mod.display("MAIN",
                    message_type="WARNING",
                    string="IOC '{}' is a {} private address and excluded from research".format(argument, type))
                continue
            if "split_observable" in config and config["split_observable"]:
                if type == "URL" or type == "domain":
                    self.extend_IOC(argument.lower(), observable_list)

            matching_list = Utils.gen_matching_type_modules_list(modules, type)
            cluster.add_cluster(argument.lower(), matching_list, dictname, conn)
            self.run(argument.lower(), type, matching_list, queues)
        # Add cluster for display INIT and MAIN logs
        cluster.add_cluster("", ["INIT", "MAIN"], dictname, conn)
        mod.display("MAIN",
                    message_type="INFO",
                    string="Every IOCs have been enqueued, BTG is processing ...")

    def extend_IOC(self, argument, observable_list):
        """
            Extending IOC from URL into URL + DOMAIN + IP
        """
        if config['offline']:
            # Cache search
            # TODO
            if "TLDE_cache" in config:
                cache_file = "%s%s" % (config['temporary_cache_path'], config['TLDE_cache'])
                cache_extract = tldextract.TLDExtract(cache_file=cache_file)
                extract = cache_extract(argument)
        else:
            # Live search
            no_cache_extract = tldextract.TLDExtract(cache_file=False)
            extract = no_cache_extract(argument)

        try:
            registered_domain = extract.registered_domain
        except:
            registered_domain = None
        try:
            suffix_domain = extract.suffix
        except:
            suffix_domain = None
        try:
            complete_domain = '.'.join(part for part in extract if part)
        except:
            complete_domain = None
        domains = [registered_domain, suffix_domain, complete_domain]

        IPs = [None, None, None]
        if not config["offline"] and config["split_observable_resolve_domain"]:
            for domain in domains:
                try:
                    IP = socket.gethostbyname(domain)
                except:
                    IP = None
                IPs.append(IP)

        for domain in domains:
            if domain is not None and domain not in observable_list:
                observable_list.append(domain)
        for IP in IPs:
            if IP is not None and IP not in observable_list:
                observable_list.append(IP)


    def run(self, argument, type, modules, queues):
        """
            Main observable module requests
        """
        mod.display(ioc=argument, string="Observable type: %s" % type)
        if type is None:
            mod.display("MAIN",
                        message_type="WARNING",
                        string="IOC : %s has an undefined type : %s" % (argument, type))
            return None

        for module in modules:
            try:
                working_going.enqueue(module_worker_request,
                                      args=(module, argument, type, queues),
                                      result_ttl=0)
            except :
                mod.display("MAIN",
                            "FATAL_ERROR",
                            "Could not enqueue the job : %s, %s, %s " % (module, argument, type))

    def checkType(self, argument):
        """
            Identify observable type
        """
        if not argument or len(argument.strip()) == 0:
            return None
        elif argument[0] == '#':
            return None
        elif validators.url(argument):
            return "URL"
        elif validators.md5(argument):
            return "MD5"
        elif validators.sha1(argument):
            return "SHA1"
        elif validators.sha256(argument):
            return "SHA256"
        elif validators.sha512(argument):
            return "SHA512"
        elif validators.ipv4(argument):
            return "IPv4"
        elif validators.ipv6(argument):
            return "IPv6"
        elif validators.domain(argument):
            return "domain"
        else:
            return None


class Utils:

    def __init__():
        return None

    def gen_module_list():
        """
            List all modules
        """
        all_files = [f for f in listdir(config["modules_folder"]) if isfile(join(config["modules_folder"], f))]
        modules = []
        for file in all_files:
            if file[-3:] == ".py" and file[:-3] != "__init__":
                modules.append(file[:-3])
        return modules

    def gen_enabled_modules_list(modules):
        """
            List all enabled modules
        """
        enabled_list = []
        for module in modules:
            if module+"_enabled" in config and config[module+"_enabled"]:
                enabled_list.append(module)
        return enabled_list

    def gen_matching_type_modules_list(modules, type):
        """
            List all modules which can support a type and are allowed to research
        """
        matching_list = []
        script_dir = dirname(__file__)
        rel_path = 'data/modules_descriptor.csv'
        abs_path = join(script_dir, rel_path)
        enabled_modules = Utils.gen_enabled_modules_list(modules)
        try:
            with open(abs_path, 'r') as csvfile:
                try:
                    reader = csv.reader(csvfile, delimiter=';')
                    for row in reader:
                        for module in modules:
                            if row:
                                if module == row[0]:
                                    types = row[1].split(',')
                                    if type in types and mod.allowedToSearch(row[2], module=module) and module in enabled_modules:
                                        matching_list.append(module)
                except:
                    mod.display("MAIN",
                                message_type="FATAL_ERROR",
                                string="Could not read %s" % abs_path)
                    sys.exit()
                finally:
                    csvfile.close()
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not open %s" % abs_path)
            sys.exit()
        return matching_list

    def show_up_errors(start_time, end_time, modules):
        """
            Count errors encountered during execution
        """
        enabled_list = Utils.gen_enabled_modules_list(modules)
        dict_list = []
        for module in enabled_list:
            dict_list.append({"module_name": module, "nb_error": 0})
        log_error_file = config["log_folder"] + config["log_error_file"]
        try:
            with open(log_error_file, "r+") as f:
                try:
                    lines = f.read().strip().splitlines()
                except:
                    mod.display("MAIN",
                                "FATAL_ERROR",
                                "Could not read %s, checkout your btg.cfg." % (log_error_file))
                    sys.exit()
                finally:
                    f.close()
        except FileNotFoundError:
            return None
        except:
            mod.display("MAIN",
                        "FATAL_ERROR",
                        "Could not open %s, checkout your btg.cfg." % (log_error_file))
            sys.exit()

        regex = re.compile("(?<=\[).*?(?=\])")
        start_time = start_time.strftime('%d-%m-%Y %H:%M:%S')
        end_time = end_time.strftime('%d-%m-%Y %H:%M:%S')
        for line in lines:
            match = regex.findall(line)
            if len(match) == 0:
                continue
            log_time = match[0]
            log_module = match[1]
            if log_time >= start_time and log_time <= end_time:
                for dict in dict_list:
                    tmp = "%s%s%s" % (colors.MODULE, dict['module_name'], colors.NORMAL)
                    if log_module == tmp:
                        dict["nb_error"] = dict["nb_error"] + 1
        return dict_list

    def motd():
        """
            Display Message Of The Day in console
        """
        motd = "%s v%s\n" % (b64decode("""
                ICAgIF9fX18gX19fX19fX19fX19fCiAgIC8gX18gKV8gIF9fLyBfX19fLwogIC8gX18gIHw\
                vIC8gLyAvIF9fICAKIC8gL18vIC8vIC8gLyAvXy8gLyAgCi9fX19fXy8vXy8gIFxfX19fLw\
                ==""".strip()).decode("utf-8"), version)
        print(motd.replace("\\n", "\n"))

    def createLoggingFolder():
        if not isdir(config["log_folder"]):
            try:
                makedirs(config["log_folder"])
            except:
                mod.display("MAIN",
                            message_type="FATAL_ERROR",
                            string="Unable to create %s directory. (Permission denied)" % config["log_folder"])
                sys.exit()
            chmod(config["log_folder"], 0o777)

    def parse_args():
        """
            Define the arguments
        """
        parser = argparse.ArgumentParser(description='Observable to qualify')
        parser.add_argument('observables',
                            metavar='observable',
                            type=str, nargs='+',
                            help='Type: [URL,MD5,SHA1,SHA256,SHA512,IPv4,IPv6,domain] or a file containing one observable per line')
        parser.add_argument("-d",
                            "--debug",
                            action="store_true",
                            help="Display debug informations")
        parser.add_argument("-o",
                            "--offline",
                            action="store_true",
                            help=("Set BTG in offline mode, meaning all modules"
                                  "described as online (i.e. VirusTotal) are desactivated"))
        parser.add_argument("-s",
                            "--silent",
                            action="store_true",
                            help="Disable MOTD")
        parser.add_argument("-e",
                            "--extend",
                            action="store_true",
                            help=("Enable observable extension, "
                                  "meaning BTG will try to find related observable, "
                                  "for instance: domain -> subdomains"))
        parser.add_argument("-j",
                            "--json",
                            action="store_true",
                            help="Asking for a JSON output to the given path, "
                                 "at variable json_folder in btg.cfg. "
                                 "Otherwise, default folder is /tmp/BTG/json")
        return parser.parse_args()

    def cleanups_lock_cache(real_path):
        for file in listdir(real_path):
            file_path = "%s%s/" % (real_path, file)
            if file.endswith(".lock"):
                mod.display("MAIN",
                            message_type="DEBUG",
                            string="Delete locked cache file: %s" % file_path[:-1])
                remove(file_path[:-1])
            else:
                if path.isdir(file_path):
                    Utils.cleanups_lock_cache(file_path)

    def subprocess_launcher():
        """
            Subprocess loop to launch rq-worker
        """
        processes = []
        max_worker = number_of_worker()
        worker_path = dirname(__file__)+'/lib/run_worker.py '
        worker_params = '%s' % (working_queue)
        worker_call = 'python3 '+worker_path+worker_params
        poller_path = dirname(__file__)+'/lib/poller.py '
        poller_params = '%s %s' % (working_queue, request_queue)
        poller_call = 'python3 '+poller_path+poller_params
        try:
            for i in range(max_worker):
                processes.append(subprocess.Popen([worker_call],
                                                  shell=True,
                                                  preexec_fn=setsid).pid)
            processes.append(subprocess.Popen([poller_call],
                                              shell=True,
                                              preexec_fn=setsid).pid)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not launch workers and/or poller subprocesses")
            sys.exit()

        supervisor_path = dirname(__file__)+'/lib/hypervisor.py '
        supervisor_params = '%d %s %s' % (getpid(), fp, working_queue)
        for process in processes:
            supervisor_params += ' '+str(process)
        supervisor_call = 'python3 '+supervisor_path+supervisor_params
        try:
            processes.append(subprocess.Popen([supervisor_call],
                                              shell=True,
                                              preexec_fn=setsid).pid)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not launch supervisor subprocess")
            sys.exit()
        return processes

    def strfdelta(tdelta, fmt):
        f = Formatter()
        d = {}
        lst = {'H': 3600, 'M': 60, 'S': 1}
        k = map(lambda x: x[1], list(f.parse(fmt)))
        rem = int(tdelta.total_seconds())
        for i in ('H', 'M', 'S'):
            if i in k and i in lst.keys():
                d[i], rem = divmod(rem, lst[i])
        return f.format(fmt, **d)

    def tune_json_output(json_output, now_str, total_modules, nb_ioc, duration_str):
        new_json = {}
        new_json["btg_version"] = version
        new_json["finished_date"] = now_str
        new_json["research_duration"] = duration_str
        new_json["total_modules"] = total_modules
        new_json["nb_ioc"] = nb_ioc
        new_json["offline_mode"] = config["offline"]
        new_json["iocs"] = []
        for ioc_element in json_output:
            modules_used_for_ioc = len(ioc_element["modules"])
            ioc_element["total_modules"] = modules_used_for_ioc
            new_json["iocs"].append(ioc_element)

        return new_json

    def save_json_output(json_output, total_modules, nb_ioc, duration_str):
        now_str = datetime.now().strftime('%d-%m-%Y_%H:%M:%S')
        json_file ="{}.json".format(now_str)
        json_file_path = "%s/%s" % (json_folder, json_file)
        json_output = Utils.tune_json_output(json_output, now_str, total_modules, nb_ioc, duration_str)
        try:
            with open(json_file_path, "w+") as f:
                try:
                    if config["display_motd"]:
                        f.write(json.dumps(json_output, indent=4))
                    else:
                        f.write(json.dumps(json_output))
                except:
                    raise IOError("Could not write in %s" % json_file_path)
                    return None
                finally:
                    f.close()
        except:
            raise IOError("Could not open %s" % json_file_path)
            return None
        try:
            chmod(json_file_path, 0o666)
        except:
            raise IOError("Could not open %s" % json_file_path)
            return None

    def args_manager(args):
        # Check if the parameter is a file or a list of observables
        if exists(args.observables[0]):
            args.file = "True"
        else:
            args.file = "False"
        # Check if debug
        if args.debug:
             config["debug"] = True
        if args.offline:
            config["offline"] = True
        # Check if silent mode
        if config["display_motd"] and not args.silent:
            Utils.motd()
        # Check if extend_IOC
        if args.extend:
            config["split_observable"] = True
        else:
            config["split_observable"] = False
        # Check if JSON response query
        global json_query, json_folder
        if args.json:
            if "json_folder" in config:
                json_folder = config["json_folder"]
            else:
                json_folder = "/tmp/BTG/json"
            if not isdir(json_folder):
                try:
                    makedirs(json_folder)
                except:
                    mod.display("MAIN",
                                "FATAL_ERROR",
                                "Unable to create %s directory. (Permission denied)" % json_folder)
                    sys.exit()
            json_query = True
        else:
            json_query = False


def main(argv=None):
    args = Utils.parse_args()
    Utils.args_manager(args)
    dir_path = path.dirname(path.realpath(__file__))
    if "modules_folder" in config and "temporary_cache_path" in config and "log_folder" in config:
        config["log_folder"] = path.join(dir_path, config["log_folder"])
        config["modules_folder"] = path.join(dir_path, config["modules_folder"])
        config["temporary_cache_path"] = path.join(dir_path, config["temporary_cache_path"])
    else:
        mod.display("MAIN",
                    message_type="FATAL_ERROR",
                    string="Please check if you have log_folder, modules_folder and temporary_cache_path \
                            field in btg.cfg")
        sys.exit()

    global working_queue, working_going, request_queue, failed_queue
    global lockname, dictname, fp
    try:
        fp = pidfile.store_pid_in_file(getpid())
    except Exception as e:
        mod.display("MAIN",
                    message_type="FATAL_ERROR",
                    string=e)
        sys.exit()

    try:
        Utils.createLoggingFolder()
        if path.exists(config["temporary_cache_path"]):
            Utils.cleanups_lock_cache(config["temporary_cache_path"])
        logSearch(args)
        # Connecting to Redis
        redis_host, redis_port, redis_password = init_redis()
        try:
            with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
                working_queue, request_queue, lockname, dictname = init_variables(redis_host, redis_port, redis_password, fp)
                working_going = Queue(working_queue, connection=conn)
                failed_queue = Queue('failed', connection=conn)
            r = redis.StrictRedis(host=redis_host, port=redis_port,
                                  password=redis_password)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not establish connection with Redis, check if you have redis_host, redis_port and maybe redis_password in /config/btg.cfg")
            sys.exit()

        processes = Utils.subprocess_launcher()
        modules = Utils.gen_module_list()
        enabled_modules = Utils.gen_enabled_modules_list(modules)
        start_time = datetime.now()

        BTG(args, enabled_modules)
        # waiting for all jobs to be done
        while True:
            if len(working_going.jobs) == 0 and r.llen(request_queue) == 0:
                break;
            time.sleep(1)

        try:
            json_output = redis_utils.shutdown(processes, working_going,
                                               failed_queue, lockname,
                                               dictname, r, sig_int=False,
                                               json_query=json_query)
        except NameError as e:
            mod.display("MAIN",
                        message_type="ERROR",
                        string=e)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not close subprocesses, here are their pid :"+"".join(['%s ' % i for i in processes]))
            try:
                remove(fp)
            except FileNotFoundError:
                pass
            except:
                mod.display("MAIN",
                            message_type="FATAL_ERROR",
                            string="Could not delete %s, make sure to delete it for next usage" % fp)
            sys.exit()

        end_time = datetime.now()
        errors_to_display = Utils.show_up_errors(start_time, end_time, modules)
        err.display(dict_list=errors_to_display)



        nb_ioc = len(observable_list)
        nb_modules = len(enabled_modules)
        delta_time = Utils.strfdelta((end_time - start_time),
                                     "{H:02}h {M:02}m {S:02}s")
        if json_query:
            try:
                json_output = json.loads(json_output)
                Utils.save_json_output(json_output, nb_modules, nb_ioc, delta_time)
            except Exception as e:
                mod.display("MAIN",
                            message_type="ERROR",
                            string="Could not save json results: %s" % e)
        mod.display("INIT", message_type="FINISHED")
        mod.display("MAIN", message_type="FINISHED")
        if config["display_end_stats"]:
            
            print("\nAll works done:\n   in %s" % (delta_time))
            if nb_ioc <= 1:
                print("   for %d IOC" % (nb_ioc))
            else:
                print("   for %d IOCs" % (nb_ioc))
            if nb_modules <= 1:
                print("   with %d module enabled\n" % (nb_modules))
            else:
                print("   with %d modules enabled\n" % (nb_modules))

        try:
            remove(fp)
        except FileNotFoundError:
            pass
        except:
            mod.display("MAIN",
                        "FATAL_ERROR",
                        "Could not delete %s, make sure to delete it for next usage" % fp)
            sys.exit()

    except (KeyboardInterrupt, SystemExit):
        '''
        Exit if user press CTRL+C
        '''
        time.sleep(1)
        print("\n%s%sA FATAL_ERROR occured or you pressed CTRL+C" % (colors.BOLD, colors.FATAL_ERROR))
        print("Closing the worker, and clearing pending jobs ...%s\n" % (colors.NORMAL))

        mod.display("INIT", message_type="FINISHED")
        mod.display("MAIN", message_type="FINISHED")

        try:
            redis_utils.shutdown(processes, working_going, failed_queue,
                                 lockname, dictname, r)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not close subprocesses, here are their pid :" + "".join(['%s ' % i.pid for i in processes]))
        try:
            remove(fp)
        except FileNotFoundError:
            pass
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not delete %s, make sure to delete it for next usage" % fp)
            sys.exit()
        sys.exit()
