#!/usr/bin/env python3
# Copyright (C) 2017  Ghent University
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
from subprocess import check_call, CalledProcessError

from charmhelpers.core import hookenv, unitdata
from charmhelpers.core.hookenv import status_set

from charms.reactive import when, when_not, set_state, remove_state

from charms.layer import lets_encrypt  # pylint:disable=E0611,E0401
from charms.layer.nginx import configure_site


db = unitdata.kv()
config = hookenv.config()


@when('apt.installed.apache2-utils')
@when_not('ssl-termination-proxy.installed')
def install():
    if not os.path.isdir('/etc/nginx/.htpasswd'):
        os.mkdir('/etc/nginx/.htpasswd')
    set_state('ssl-termination-proxy.installed')


@when('ssl-termination-proxy.installed')
@when_not('ssltermination.available')
def signal_need_webservice():
    status_set('blocked', 'Please relate a SSL Termination client')


@when('ssltermination.connected')
def check_status(ssltermination):
    ssltermination.check_status()


@when('ssl-termination-proxy.installed', 'ssltermination.available')
def pre_setup(ssltermination):
    status_set('maintenance', 'SSL termination relation found, configuring proxy')
    received_fqdns = []
    received_basic_auth = []
    received_private_ips = []
    received_loadbalancing = []
    fqdns = db.get('fqdns', [])
    basic_auth = db.get('basic_auth', [])
    private_ips = db.get('private_ips', [])
    loadbalancing = db.get('loadbalancing', [])
    for data in ssltermination.get_data():
        received_fqdns.extend(data['fqdns'])
        received_basic_auth.extend(data['basic_auth'])
        received_private_ips.extend(data['private_ips'])
        received_loadbalancing.append(data['loadbalancing'])
    if fqdns != received_fqdns:
        db.set('fqdns', received_fqdns)
        lets_encrypt.update_fqdns()
        remove_state('ssl-termination-proxy.running')
    else:
        status_set('active', '{} have been registered and are online'.format(db.get('fqdns')))
    if basic_auth != received_basic_auth:
        db.set('basic_auth', received_basic_auth)
        remove_state('ssl-termination-proxy.running')
    else:
        status_set('active', '{} have been registered and are online'.format(db.get('fqdns')))
    if private_ips != received_private_ips:
        db.set('private_ips', received_private_ips)
        remove_state('ssl-termination-proxy.running')
    else:
        status_set('active', '{} have been registered and are online'.format(db.get('fqdns')))
    if loadbalancing != received_loadbalancing:
        db.set('loadbalancing', received_loadbalancing)
        remove_state('ssl-termination-proxy.running')
    else:
        status_set('active', '{} have been registered and are online'.format(db.get('fqdns')))


@when('ssl-termination-proxy.installed', 'ssltermination.available', 'lets-encrypt.registered')
@when_not('ssl-termination-proxy.running')
def setup(ssltermination):
    live = lets_encrypt.live(db.get('fqdns'))
    for data in ssltermination.get_data():
        service = data['service']
        try:
            os.remove('/etc/nginx/.htpasswd/{}'.format(service))
        except OSError:
            pass
        # Did we get credentials? If so, configure them.
        for user in data['basic_auth']:
            try:
                check_call([
                    'htpasswd', '-b', '/etc/nginx/.htpasswd/{}'.format(service),
                    user['name'], user['password']])
            except CalledProcessError:
                check_call([
                    'htpasswd', '-bc', '/etc/nginx/.htpasswd/{}'.format(service),
                    user['name'], user['password']])
        configuration = {
            'privkey': live['privkey'],
            'fullchain': live['fullchain'],
            'service': service,
            'servers': data['private_ips'],
            'fqdns': data['fqdns'],
            'dhparam': live['dhparam'],
            'auth_basic': bool(data['basic_auth'])
        }
        if data['loadbalancing']:
            configuration['loadbalancing'] = data['loadbalancing']
        configure_site('{}.conf'.format(service), 'service.conf', **configuration)
    set_state('ssl-termination-proxy.running')
    status_set('active', '{} have been registered and are online'.format(db.get('fqdns')))
