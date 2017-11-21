import json
import requests
import os
import subprocess
import uuid

def getVendordataFromMetadataAPI():
  response = requests.get(
    'http://169.254.169.254/openstack/latest/vendor_data2.json',
  )
  assert response.status_code == 200
  return json.loads(response.content)

def getInstanceAndProjectIdFromMetadataAPI():
  response = requests.get(
    'http://169.254.169.254/openstack/latest/meta_data.json',
  )
  assert response.status_code == 200
  metadata = json.loads(response.content)
  assert 'uuid' in metadata
  assert 'project_id' in metadata
  return metadata['uuid'], metadata['project_id']

def getVendordataFromConfigDrive():
  path = '/mnt/config/openstack/latest/vendor_data2.json'
  with open(path, 'r') as f:
    json_string = f.read()
    return json.loads(json_string)

def getInstanceAndProjectIdFromConfigDrive():
  path = '/mnt/config/openstack/latest/meta_data.json'
  with open(path, 'r') as f:
    json_string = f.read()
    metadata = json.loads(json_string)
  assert 'uuid' in metadata
  assert 'project_id' in metadata
  return str(uuid.UUID(metadata['uuid'], version=4)), str(uuid.UUID(metadata['project_id'], version=4))

vendordata = getVendordataFromConfigDrive()
#vendordata = getVendordataFromMetadataAPI()
instance_id, project_id = getInstanceAndProjectIdFromConfigDrive()
#instance_id, project_id = getInstanceIdFromMetadataAPI()

assert 'tatu' in vendordata
tatu = vendordata['tatu']
assert 'token' in tatu
assert 'auth_pub_key_user' in tatu
assert 'principals' in tatu
principals = tatu['principals'].split(',')

with open('/etc/ssh/ssh_host_rsa_key.pub', 'r') as f:
  host_key_pub = f.read()

server = 'http://172.24.4.1:18321'

hostcert_request = {
  'token_id': tatu['token'],
  'host_id': instance_id,
  'key.pub': host_key_pub
}

response = requests.post(
  # Hard-coded SSHaaS API address will only work for devstack and requires
  # routing and SNAT or DNAT.
  # This eventually needs to be either:
  # 1) 169.254.169.254 if there's a SSHaaS-proxy; OR
  # 2) the real address of the API, possibly supplied in the vendordata and
  #    still requiring routing and SNAT or DNAT.
  server + '/hostcerts',
  data=json.dumps(hostcert_request)
)
assert response.status_code == 201
assert 'location' in response.headers
location = response.headers['location']
print location

response = requests.get(server + location)
hostcert = json.loads(response.content)
assert 'host_id' in hostcert
assert hostcert['host_id'] == instance_id
assert 'fingerprint' in hostcert
assert 'auth_id' in hostcert
auth_id = str(uuid.UUID(hostcert['auth_id'], version=4))
assert auth_id == project_id
assert 'key-cert.pub' in hostcert

# Write the host's certificate
with open('/etc/ssh/ssh_host_rsa_key-cert.pub', 'w') as f:
  f.write(hostcert['key-cert.pub'])

# Write the authorized principals file
os.mkdir('/etc/ssh/auth_principals')
with open('/etc/ssh/auth_principals/ubuntu', 'w') as f:
  for p in principals:
    f.write(p + os.linesep)

# Write the User CA public key file
with open('/etc/ssh/ca_user.pub', 'w') as f:
  f.write(tatu['auth_pub_key_user'])

subprocess.check_output("sed -i -e '$aTrustedUserCAKeys /etc/ssh/ca_user.pub' /etc/ssh/sshd_config")
subprocess.check_output("sed -i -e '$aAuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' /etc/ssh/sshd_config")
subprocess.check_output("sed -i -e '$aHostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub' /etc/ssh/sshd_config")
subprocess.check_output("systemctl restart ssh")