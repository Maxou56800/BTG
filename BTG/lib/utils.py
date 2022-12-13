#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Conix Cybersecurity
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

from rq import Worker
import json
import os
import re
import signal
import time
import uuid

from BTG.lib.config_parser import Config

config = Config.get_instance()

class cluster:
    def __init__():
        return None

    def get_keys(fp):
        lockname = None
        dictname = None
        with open(fp, 'r') as pf:
                main_pid = pf.read().strip().splitlines()
                lockname = "lock:%s" % (main_pid[0])
                dictname = "dict:%s" % (main_pid[0])
                pf.close()
        return lockname, dictname

    def remove_keys(conn, lockname, dictname):
        conn.delete(lockname)
        conn.delete(dictname)

    def acquire_lock(conn, lockname):
        id = str(uuid.uuid4())
        while True:
            if conn.setnx(lockname, id):
                return id
            time.sleep(0.1)
        return False

    def release_lock(conn, lockname, id):
        while True:
            value = conn.get(lockname).decode("utf-8")
            if value == id:
                conn.delete(lockname)
                return True
            time.sleep(0.1)

    def add_cluster(ioc, modules, dictname, conn):
        cluster = {
            'ioc': ioc,
            'modules': modules,
            'total_module': 0,
            'module_finished': 0,
            'has_found': False,
            'messages': {}
        }
        for module in modules:
            if module == "cuckoosandbox":
                cluster['total_module'] = cluster['total_module'] + len(config['cuckoosandbox_api_url'])
            elif module == "viper":
                cluster['total_module'] = cluster['total_module'] + len(config['viper_server'])
            elif module == "misp":
                cluster['total_module'] = cluster['total_module'] + len(config['misp_url'])
            elif module == "mwdb":
                cluster['total_module'] = cluster['total_module'] + len(config['mwdb_api_url'])
            else:
                cluster['total_module'] = cluster['total_module'] + 1
            cluster['messages'][module] = []
        conn.lpush(dictname, json.dumps(cluster))

    def edit_cluster(ioc, module, message, conn, lockname, dictname):
        c = None
        locked = cluster.acquire_lock(conn, lockname)
        bytes_clusters = conn.lrange(dictname, 0, -1)
        for bytes_cluster in bytes_clusters:
            try:
                c = json.loads(bytes_cluster.decode("utf-8"))
                if c['ioc'] == ioc and module in c['modules']:
                    if message["type"] == "FINISHED":
                        c['module_finished'] = c['module_finished'] + 1
                    if message["type"] == "FOUND":
                        c['has_found'] = True
                    c['messages'][module].append(message)
                    conn.lrem(dictname, 1, bytes_cluster)
                    json_cluster = json.dumps(c)
                    conn.lpush(dictname, json_cluster)
                    if message["type"] != "FINISHED":
                        c = None
                    break
                else:
                    c = None
            except:
                c = None
        cluster.release_lock(conn, lockname, locked)
        return c

    def allowed_to_display(message_type):
        if message_type == "FOUND":
            return True
        elif message_type == "NOT_FOUND" and config["display_not_found"]:
            return True
        elif message_type == "WARNING" and config["display_warnings"]:
            return True
        elif message_type == "ERROR" and config["display_errors"]:
            return True
        elif message_type in ["INFO", "FINISHED"] and config["display_info"]:
            return True
        elif message_type == "DEBUG" and config["debug"]:
            return True
        return False

    def has_message(cluster_elements):
        has_message = False
        for module in cluster_elements["messages"]:
            if len(cluster_elements["messages"][module]):
                has_message = True
        return has_message

    def print_cluster(cluster_elements, conn):
        if not cluster_elements:
            return None
        if cluster_elements["total_module"] != cluster_elements["module_finished"]:
            #print("[{}]]Module completed: {} / {}".format(cluster_elements["ioc"], cluster_elements["total_module"], cluster_elements["module_finished"]))
            return None
        new_line = False
        has_found = cluster_elements["has_found"]
        ioc_color = "" 
        ioc_endcolor = ""
        if has_found:
            ioc_color = "\033[38;5;10m" # Green
            ioc_endcolor = "\033[0m" # ENDC
        if not cluster.has_message(cluster_elements):
            return None
        something_to_display = False
        if len(cluster_elements["messages"]):
            for module in cluster_elements["messages"]:
                for message in cluster_elements["messages"][module]:
                    if cluster.allowed_to_display(message['type']):
                        something_to_display = True
            if cluster_elements["ioc"] == "":
                pass
                #print("=== INIT/MAIN ===")
            else:
                if something_to_display:
                    print("=== IOC: {}{}{} ===".format(ioc_color,
                                                   cluster_elements["ioc"],
                                                   ioc_endcolor))
        for module in cluster_elements["messages"]:
            for message in cluster_elements["messages"][module]:
                if cluster.allowed_to_display(message['type']):
                    new_line = True
                    print(message['string'])
        if new_line:
            pass
            print('')

    def get_clusters(dictname, conn):
        bytes_clusters = conn.lrange(dictname, 0, -1)
        outputs = []
        for bytes_cluster in bytes_clusters:
            outputs.append(json.loads(bytes_cluster.decode("utf-8")))
        regex = r'\033.+?(?=m)m'
        for output in outputs:
            for module in output["messages"]:
                for message in output["messages"][module]:
                    matches = re.findall(regex, message['string'])
                    for match in matches:
                        message['string'] = message['string'].replace(match, '', 1)
        json_output = json.dumps(outputs)
        return json_output


class pidfile:
    def __init__():
        return None

    # Make directory for temporary pidfile if it does not exist
    def make_pidfile_dir():
        abs_path = "/tmp/BTG/data"
        if not os.path.isdir(abs_path):
            try:
                os.makedirs(abs_path)
                os.chmod(abs_path, 0o770)
            except:
                raise OSError("Could not make directory :/tmp/BTG/data")
        return abs_path

    # Check if pidfile exists and return his path
    def exists_pidfile(dir):
        for file in os.listdir(dir):
            if file.endswith(".pid"):
                file_path = os.path.join(dir, file)
                return file_path
        return dir

    def store_pid_in_file(pid):
        try:
            dir_path = pidfile.make_pidfile_dir()
        except:
            raise OSError("Could not make directory: /tmp/BTG/data")
        file_path = pidfile.exists_pidfile(dir_path)
        if file_path != dir_path:
            # An instance of BTG has been found, we should wait to avoid conflict
            print('\033[38;5;9m'+"An instance of BTG is already running, we will wait 30s or until its completion"+'\033[0m')
            timeout = time.time() + 30
            while time.time() < timeout:
                time.sleep(3)
                file_path = pidfile.exists_pidfile(dir_path)
                if file_path == dir_path:
                    print('\033[38;5;10m'+"Previous BTG instance is over, we start processing\n"+'\033[0m')
                    filename = "%s.pid" % pid
                    file_path = os.path.join(dir_path, filename)
                    try:
                        with open(file_path, "w+") as pf:
                            try:
                                pf.write('%d' % pid)
                            except:
                                raise IOError("Could not write in %s" % file_path)
                                return None
                            finally:
                                pf.close()
                    except:
                        raise IOError("Could not open %s" % file_path)
                        return None
                    return file_path
            raise TimeoutError("We have reached maximum waiting time, BTG is closing ...\n")
            return None
        else:
            filename = "%s.pid" % pid
            file_path = os.path.join(dir_path, filename)
            try:
                with open(file_path, "w+") as pf:
                    try:
                        pf.write('%d' % pid)
                    except:
                        raise IOError("Could not write in %s" % (file_path))
                    finally:
                        pf.close()
            except:
                raise IOError("Could not open %s" % (file_path))
        return file_path


class redis_utils:
    def __init__():
        return None

    def graceful_shutdown(working_going):
        # DO-WHILE loop to check if a worker is still working
        is_busy = True
        while is_busy:
            states = []
            workers = Worker.all(queue=working_going)
            for worker in workers:
                state = worker.get_state()
                states.append(state)
            for state in states:
                if state == 'busy':
                    is_busy = True
                    break
                is_busy = False
            time.sleep(1)
        time.sleep(1)

    def shutdown(processes_pid, working_going, failed_queue, lockname,
                 dictname, redis_conn, sig_int=True, json_query=False):
        ret = None
        if not sig_int:
            redis_utils.graceful_shutdown(working_going)

        # Removing undone jobs
        working_going.delete(delete_jobs=True)
        # Killing all processes in the group
        for process_pid in processes_pid:
            pgrp = int(process_pid)
            os.killpg(pgrp, signal.SIGTERM)
        time.sleep(1)
        failed_queue.empty()
        if json_query:
            try:
                ret = cluster.get_clusters(dictname, redis_conn)
            except Exception as e:
                raise NameError(e)

        cluster.remove_keys(redis_conn, lockname, dictname)
        return ret
