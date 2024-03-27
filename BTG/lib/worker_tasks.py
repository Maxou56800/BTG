#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tanguy Becam
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

import importlib

from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod

config = Config.get_instance()


def module_worker_request(module, argument, type, queues):
    """
        Load modules in python instance to build url to request
    """
    mod.display(string=f"Load: {config['modules_folder']}{module}.py")
    obj = importlib.import_module(f"BTG.modules.{module}")
    for c in dir(obj):
        if module+"_enabled" in config:
            if module == c.lower() and config[module+"_enabled"]:
                getattr(obj, c)(argument, type, config, queues)
        else:
            mod.display("worker_tasks",
                        message_type="INFO",
                        string=f"Module : {module} -- not configured")


def module_worker_response(response_text, response_status, module,
                           ioc, ioc_type, server_id=0):
    """
        Load modules in python instance to treat the response
    """
    obj = importlib.import_module(f"BTG.modules.{module}")
    try:
        obj.response_handler(response_text, response_status,
                             module, ioc, ioc_type, server_id)
    except:
        mod.display("worker_tasks",
                    message_type="ERROR",
                    string=f"Something went wrong when worker try to load response_handler from {module}")