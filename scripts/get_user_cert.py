import json
import requests
import os
import subprocess
import uuid
from Crypto.PublicKey import RSA

keyfile = '/opt/stack/.ssh/mykey'
user_id = str(uuid.uuid4())
auth_id = str(uuid.UUID('0852c6cd6209425c88de582acbcd1170', version=4))
key = RSA.generate(2048)
keytxt = key.exportKey('PEM')
pubkeytxt = key.publickey().exportKey('OpenSSH')
server = 'http://127.0.0.1:18321'

with open('/etc/ssh/ssh_host_rsa_key.pub', 'r') as f:
  host_key_pub = f.read()


user = {
    'user_id': user_id,
    'auth_id': auth_id,
    'key.pub': pubkeytxt
}

response = requests.post(
  server + '/usercerts',
  data=json.dumps(user)
)
assert response.status_code == 201
assert 'location' in response.headers
location = response.headers['location']
print location

response = requests.get(server + location)
usercert = json.loads(response.content)
assert 'user_id' in usercert
assert usercert['user_id'] == user_id
assert 'fingerprint' in usercert
assert 'auth_id' in usercert
au = str(uuid.UUID(usercert['auth_id'], version=4))
assert au == auth_id
assert 'key-cert.pub' in usercert

# Write the user's ID
with open(keyfile + '_user_id', 'w') as f:
  f.write(user_id)

# Write the user private key
with open(keyfile, 'w') as f:
  f.write(keytxt)

# Write the user public key
with open(keyfile + '.pub', 'w') as f:
  f.write(pubkeytxt)

# Write the user certificate
with open(keyfile + '-cert.pub', 'w') as f:
  f.write(usercert['key-cert.pub'])
