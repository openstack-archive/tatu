#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import os
import requests
import sshpubkeys
import uuid
from Crypto.PublicKey import RSA

from tatu.utils import random_uuid

server = 'http://172.24.4.1:18322'


def vendordata_request(instance_id, project_id, hostname):
    return {
        'instance-id': instance_id,
        'project-id': project_id,
        'hostname': hostname
    }


def host_request(token, host, pub_key):
    return {
        'token_id': token,
        'host_id': host,
        'key.pub': pub_key
    }


def test_host_certificate_generation():
    project_id = random_uuid()
    response = requests.post(
        server + '/authorities',
        data=json.dumps({'auth_id': project_id})
    )
    assert response.status_code == 201
    assert 'location' in response.headers
    assert response.headers['location'] == '/authorities/' + project_id

    response = requests.get(server + response.headers['location'])
    assert response.status_code == 200
    auth = json.loads(response.content)
    assert 'auth_id' in auth
    assert auth['auth_id'] == project_id
    assert 'user_key.pub' in auth
    assert 'host_key.pub' in auth
    ca_user = auth['user_key.pub']

    key = RSA.generate(2048)
    pub_key = key.publickey().exportKey('OpenSSH')
    fingerprint = sshpubkeys.SSHKey(pub_key).hash_md5()
    for i in range(1):
        instance_id = random_uuid()
        hostname = 'host{}'.format(i)
        # Simulate Nova's separate requests for each version of metadata API
        vendordata = None
        token = None
        for j in range(3):
            response = requests.post(
                server + '/novavendordata',
                data=json.dumps(
                    vendordata_request(instance_id, project_id, hostname))
            )
            assert response.status_code == 201
            assert 'location' in response.headers
            location_path = response.headers['location'].split('/')
            assert location_path[1] == 'hosttokens'
            vendordata = json.loads(response.content)
            assert 'token' in vendordata
            tok = vendordata['token']
            if token is None:
                token = tok
            else:
                assert token == tok
            assert token == location_path[-1]
            assert 'auth_pub_key_user' in vendordata
            assert vendordata['auth_pub_key_user'] == ca_user
            assert 'principals' in vendordata
            assert vendordata['principals'] == 'admin'

        response = requests.post(
            server + '/noauth/hostcerts',
            data=json.dumps(host_request(token, instance_id, pub_key))
        )
        assert response.status_code == 201
        assert 'location' in response.headers
        location = response.headers['location']
        location_path = location.split('/')
        assert location_path[1] == 'hostcerts'
        assert location_path[2] == instance_id
        assert location_path[3] == fingerprint

        response = requests.get(server + location)
        assert response.status_code == 200
        hostcert = json.loads(response.content)
        assert 'host_id' in hostcert
        assert hostcert['host_id'] == instance_id
        assert 'fingerprint' in hostcert
        assert hostcert['fingerprint']
        assert 'auth_id' in hostcert
        auth_id = str(uuid.UUID(hostcert['auth_id'], version=4))
        assert auth_id == project_id
        assert 'key-cert.pub' in hostcert
