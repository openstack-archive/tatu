def generateCert(auth_key, entity_key, host_name=None):
    # Temporarily write the authority private key and entity public key to /tmp
    ca_file = '/tmp'.join(uuid.uuid4().hex)
    pub_prefix = uuid.uuid4().hex
    pub_file = ''.join('/tmp/', pub_prefix, '.pub')
    with open(ca_file, "w") as text_file:
      text_file.write(auth_key)
    with open(pub_file, "w") as text_file:
      text_file.write(entity_key)
    # Call keygen
    if host_name is None:
      subprocess.call(['ssh-keygen', '-P "pino"', '-s', ca_file, '-I testID', '-V -1d:+365d', '-n "myRoot,yourRoot"', pub_file], shell=True)
    else:
      subprocess.call(['ssh-keygen', '-P "pino"', '-s', ca_file, '-I testID', '-V -1d:+365d', '-n', host_name, '-h', pub_file], shell=True)
    # Read the contents of the certificate file
    cert_file = ''.join('/tmp/', pub_prefix, '-cert.pub')
    cert = ''
    with open(cert_file, 'r') as text_file:
      cert = text_file.read()
    # Delete temporary files
    for file in [ca_file, pub_file, cert_file]:
      os.remove(file)
    return cert

