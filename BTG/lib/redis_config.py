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

import uuid
import os
from BTG.lib.config_parser import Config
from BTG.lib.utils import cluster

config = Config.get_instance()


def init_redis():
    """
        Full fill connection parameters for redis, see config/config.ini
    """
    redis_host, redis_port, redis_password = None, None, None
    if 'redis_host' in config and not config['redis_host'] is None:
        redis_host = config['redis_host']
    if 'redis_port' in config and not config['redis_port'] is None:
        redis_port = config['redis_port']
    if 'redis_password' in config:
        redis_password = config['redis_password']
    if os.environ.get('REDIS_HOST', None):
        redis_host = os.environ.get('REDIS_HOST')
    if os.environ.get('REDIS_PORT', None):
        redis_host = os.environ.get('REDIS_PORT')
    if os.environ.get('REDIS_PASSWORD', None):
        redis_host = os.environ.get('REDIS_PASSWORD')
    return redis_host, redis_port, redis_password


def init_variables(redis_host, redis_port, redis_password, fp):
    """
        Producing a random name for global variables : queues, lock, dict,
        thus we can run multiple instance of BTG
    """
    working_queue = 'rq-queue:'+str(uuid.uuid4())
    request_queue = 'r-list:'+str(uuid.uuid4())
    lockname, dictname = cluster.get_keys(fp)
    return working_queue, request_queue, lockname, dictname


def init_worker():
    """
        Specifying worker options : [burst, logging_level]
    """
    burst = False
    logging_level = "ERROR"
    return burst, logging_level


def number_of_worker():
    """
        Number of worker to launch
    """
    if 'max_worker' in config and config['max_worker'] > 0:
        max_worker = config['max_worker']
    else:
        max_worker = 4
    return max_worker
