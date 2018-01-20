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

import base64
import os
import shutil
import subprocess
import uuid
from tempfile import mkdtemp


def random_uuid():
    return str(uuid.uuid4())


def generateCert(auth_key, entity_key, user=True, principals='root', serial=0):
    # Temporarily write the authority private key, entity public key to files
    temp_dir = mkdtemp()
    ca_file = '/'.join([temp_dir, 'ca_key'])
    pub_file = '/'.join([temp_dir, 'entity.pub'])
    cert_file = '/'.join([temp_dir, 'entity-cert.pub'])
    cert = ''
    try:
        fd = os.open(ca_file, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        with open(ca_file, "w") as text_file:
            text_file.write(auth_key)
        with open(pub_file, "w", 0o644) as text_file:
            text_file.write(entity_key)
        args = ['ssh-keygen', '-s', ca_file, '-I', 'testID', '-V',
                '-1d:+365d', '-z', str(serial)]
        if user:
            args.extend(['-n', principals, pub_file])
        else:
            args.extend(['-h', pub_file])
        subprocess.check_output(args, stderr=subprocess.STDOUT)
        # Read the contents of the certificate file
        with open(cert_file, 'r') as text_file:
            cert = text_file.read()
    finally:
        shutil.rmtree(temp_dir)
    return cert


def revokedKeysBase64(ca_public, serial_list):
    # Temporarily write the authority private key and list of serials
    temp_dir = mkdtemp()
    ca_file = '/'.join([temp_dir, 'ca_public'])
    serials_file =  '/'.join([temp_dir, 'serials'])
    revoked_file = '/'.join([temp_dir, 'revoked'])
    try:
        with open(ca_file, "w", 0o644) as text_file:
            text_file.write(ca_public)
        with open(serials_file, "w", 0o644) as text_file:
            for s in serial_list:
                text_file.write("serial: {}\n".format(s))
        args = ['ssh-keygen', '-k', '-f', revoked_file, '-s', ca_file, serials_file]
        subprocess.check_output(args, stderr=subprocess.STDOUT)
        # Return the base64 encoded contents of the revoked keys file
        with open(revoked_file, 'r') as text_file:
            b64data = base64.b64encode(text_file.read())
    finally:
        shutil.rmtree(temp_dir)
    return b64data
