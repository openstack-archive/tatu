import json
import requests
import os
import subprocess

def getVendordataFromMetadataAPI():
  response = requests.get(
    'http://169.254.169.254/openstack/2016-10-06/vendor_data2.json',
  )
  assert response.status_code == 200
  return json.loads(response.content)

def getVendordataFromConfigDrive():
  path = '/mnt/openstack/2016-10-06/vendor_data2.json'
  with open(path, 'r') as f:
    json_string = f.read()
    return json.loads(json_string)

def getInstanceAndProjectIdFromMetadataAPI():
  response = requests.get(
    'http://169.254.169.254/openstack/latest/meta_data.json',
  )
  assert response.status_code == 200
  metadata = json.loads(response.content)
  assert 'uuid' in metadata
  assert 'project_id' in metadata
  return metadata['uuid'], metadata['project_id']

def getInstanceAndProjectIdFromConfigDrive():
  path = '/mnt/openstack/latest/meta_data.json'
  with open(path, 'r') as f:
    json_string = f.read()
    metadata = json.loads(json_string)
  assert 'uuid' in metadata
  assert 'project_id' in metadata
  return metadata['uuid'], metadata['project_id']

#vendordata = getVendordataFromConfigDrive()
vendordata = getVendordataFromMetadataAPI()
#instance_id = getInstanceIdFromConfigDrive()
instance_id, project_id = getInstanceIdFromMetadataAPI()

assert 'sshaas' in vendordata
sshaas = vendordata['sshaas']
assert 'token' in sshaas
assert 'auth_pub_key_user' in sshaas
assert 'principals' in sshaas
principals = sshaas['principals'].split(',')

with open('~/.ssh/id_rsa.pub', 'r') as f:
  host_key_pub = f.read()

hostcert_request = {
  'token_id': sshaas['token'],
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
  'http://localhost:8000/hostcerts',
  data=json.dumps(hostcert_request)
)
assert response.status_code == 201
assert 'location' in response.headers
location = response.headers['location']

response = requests.get(
  'http://169.254.169.254' + location
)
hostcert = json.loads(response.content)
assert 'host_id' in metadata
assert metadata['host_id'] == instance_id
assert 'fingerprint' in metadata
assert 'auth_id' in metadata
assert metadata['auth_id'] == project_id
assert 'key-cert.pub' in metadata

# Write the host's certificate
with open('/etc/ssh/ssh_host_rsa_key-cert.pub', 'w') as f:
  f.write(metadata['key-cert.pub'])

# Write the authorized principals file
os.mkdir('/etc/ssh/auth_principals')
with open('/etc/ssh/auth_principals/ubuntu', 'w') as f:
  for p in principals:
    f.write(p + os.linesep)

# Write the UserCA public key file
with open('/etc/ssh/user_ca.pub', 'w') as f:
  f.write(sshaas['auth_pub_key_user'])

subprocess.check_output("sed -i -e '$aTrustedUserCAKeys /etc/ssh/user_ca.pub' /etc/ssh/sshd_config")
subprocess.check_output("sed -i -e '$aAuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' /etc/ssh/sshd_config")
subprocess.check_output("set -i -e '$aHostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub' /etc/ssh/sshd_config")
subprocess.check_output("systemctl restart ssh")
