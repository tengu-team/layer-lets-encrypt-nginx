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
from subprocess import check_call

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
    set_state('ssl-termination-proxy.installed')


@when('ssl-termination-proxy.installed')
@when_not('ssltermination.available')
def signal_need_webservice():
    status_set('blocked', 'Please relate a SSL Termination client')


@when('ssltermination.connected')
@when_not('ssltermination.available')
def check_status(ssltermination):
    ssltermination.check_status()


@when('ssl-termination-proxy.installed', 'ssltermination.available')
@when_not('lets-encrypt.registered')
def setup_fqdns(ssltermination):
    data = ssltermination.get_data()[0]
    fqdns = db.get('fqdns')
    if fqdns is None:
        db.set('fqdns', data['fqdns'])
    else:
        db.set('fqdns', list(set(fqdns) | set(data['fqdns'])))
    lets_encrypt.update_fqdns()


@when('ssl-termination-proxy.installed', 'ssltermination.available', 'lets-encrypt.registered')
def set_up(ssltermination):
    print('SSL termination relation found, configuring proxy.')
    data = ssltermination.get_data()[0]
    service = data['service']
    try:
        os.remove('/etc/nginx/.htpasswd/{}'.format(service))
    except OSError:
        pass
    # Did we get credentials? If so, configure them.
    for user in data['basic_auth']:
        check_call([
            'htpasswd', '-b', '/etc/nginx/.htpasswd/{}'.format(service),
            user['name'], user['password']])
    live = lets_encrypt.live(data['fqdns'])
    configure_site(
        'serivce.conf', '{}.conf'.format(service),
        privkey=live['privkey'],
        fullchain=live['fullchain'],
        loadbalancing=data['loadbalancing'],
        service=service,
        servers=data['private_ips'],
        fqdns=data['fqdns'],
        dhparam=live['dhparam'],
        auth_basic=bool(data['basic_auth']))
    set_state('ssl-termination-proxy.running')
    status_set('active', '{} have been registered and are online'.format(', '.join(data['fqdns'])))


@when('ssl-termination-proxy.running', 'ssltermination.removed')
def remove_fqdns(ssltermination):
    data = ssltermination.get_data()[0]
    db.set('fqdns', list(set(db.get('fqdns')) - set(data['fqdns'])))
    lets_encrypt.update_fqdns()
