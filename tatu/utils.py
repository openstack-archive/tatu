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

import os
import shutil
import subprocess
from tempfile import mkdtemp
import uuid


def random_uuid():
    return str(uuid.uuid4())


def generateCert(auth_key, entity_key, hostname=None, principals='root'):
    # Temporarily write the authority private key, entity public key to files
    prefix = uuid.uuid4().hex
    # Todo: make the temporary directory configurable or secure it.
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
                '-1d:+365d']
        if hostname is None:
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
