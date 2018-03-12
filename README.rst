===================================
Tatu - OpenStack's SSH-as-a-Service
===================================

Named in honor of Tatu Ylönen, the inventor of SSH, Tatu is an OpenStack
service that manages user and host SSH certificates. Tatu can also start and
manage bastion servers so that you don't have to (and so you don't have to give
every SSH server a public IP address).

Tatu uses Barbican to store two private keys per OpenStack project:

* A User CA (Certificate Authority) key is used to sign a user public key, thus
  creating an SSH user certificate.
* A Host CA key is used to sign the SSH server's public key, thus creating an
  SSH host certificate.

Tatu provides APIs that allow:

* OpenStack users to obtain SSH certificates (project-scoped) for public keys
  of their choosing, with permissions corresponding to their roles in the
  project). The SSH certificate is usually placed in ~/.ssh/id_rsa-cert.pub
* OpenStack users to obtain the public key of the CA that signs host
  certificates. This is placed in the user's known_hosts file.
* OpenStack VM (or bare metal) instances to obtain a host SSH certificate for
  their public key, and to learn the public key of the CA for users.

During VM provisioning:

* Tatu's cloud-init script is passed to the VM via Nova **static** vendor data.
* VM-specific configuration is placed in the VM's ConfigDrive thanks to Nova's
  **dynamic** vendor data call to Tatu API.
* The cloud-init script consumes the dynamic vendor data:

  * A one-time-token is used to authenticate the VM's request to Tatu API to
    sign the VM's public key (and return and SSH host certificate).
  * A list of the VM's project's Keystone roles is used to create user accounts
    on the VM.
  * A list of sudoers is used to decide which users get password-less sudo
    privileges. The current policy is that any Keystone role containing "admin"
    should correspond to a user account with sudo privileges.
  * The public key of the CA for User SSH certificates is retrieved, and along
    with the requested SSH Host Certificate, is used to (re)configure SSH.

* A cron job is configured for the VM to periodically poll Tatu for the revoked
  keys list.

During negotiation of the SSH connection:

#. The server presents its SSH host certificate.
#. The client checks the validity of the host certificate, by checking its
   signature with the Host CA public key stored in the known_hosts file
   (in a config line that starts with @cert-authority <domain>).
#. The client presents its SSH client certificate.
#. The server checks the validity of the client certificate, by checking its
   signature with the User CA public key stored in the file configured in
   sshd_config's TrustedUserCAKeys.
#. The server also checks that the certificate has not been revoked, for
   example that its serial number isn't in the file configured in ssh_config's
   RevokedKeys setting.
#. The client certificate also contains a list of principals that in Tatu's
   case correspond to the user's role assignments in the project and give
   access to user accounts with the same name.

Use of host certificates prevents MITM (man in the middle) attacks. Without
host certificates, users of SSH client software are presented with a message
like this one when they first connect to an SSH server::

    The authenticity of host '111.111.11.111 (111.111.11.111)' can't be established.
    ECDSA key fingerprint is fd:fd:d4:f9:77:fe:73:84:e1:55:00:ad:d6:6d:22:fe.
    Are you sure you want to continue connecting (yes/no)?

There's no way to verify the fingerprint unless there's some other way of
logging into the VM (e.g. novnc with password - whhich is not recommended).

It should be obvious that using certificates SSH servers only need to store the
user CA public key (and a digest of revoked client certificates), not every
client certificate. This is simpler, more secure and more manageable than
today's common practice: putting each user's public key in the SSH server's
authorized_keys file.

Installation
------------

Please see the INSTALLATION document in this repository. Then see the TRY_IT
document as well for step by step instructions on using it.

APIs, Horizon Panels, and OpenStack CLIs
----------------------------------------

Tatu provides REST APIs, Horizon Panels and OpenStack CLIs to:

* Retrieve the public keys of the user and host CAs for each OpenStack project.
  See ssh ca --help
* Create (and revoke) SSH user certificates with principals corresponding to
  the OpenStack user's role assignments. See ssh usercert --help
* Create and view SSH host certificates. See ssh hostcert --help
* Get the bastion addresses for each SSH server and their DNS records. See
  ssh host --help

VM access to Tatu's API
-----------------------

Tatu does not currently generate SSH keys for VMs (although we may consider
this feature later since Barbican may be able to generate better quality
keys).

On first boot, the VM calls Tatu's */hostcerts* API to request a
host certificate. It passes as parameters the SSH public key (currently the RSA
key) and a one-time-token. The one-time token was previously generated by Tatu
on a request by Nova for dynamic vendor data, and then passed to the VM via
ConfigDrive.

The VM also periodically (every 60 seconds) calls Tatu's */revokeduserkeys* API
to refresh its local revoked-keys file (configured via RevokedKeys in
sshd_config).

The VM's access to the Tatu API must currently go over http (not https) and
cannot be authenticated via Keystone. We aim to improve this in the future. We
therefore expose the /hostcerts and /revokeduserkeys APIs without
authentication (with a /noauth path prefix). The one-time-token prevents
malicious users from generating host certificates. The /hosttokens API to
generate one-time-tokens is only accessible with Keystone authentication, can
be secured with TLS, and is only meant to be called by Nova's dynamic vendor
data mechanism.

In order to further secure Tatu's /noauth path, we intend to have VMs access
Tatu's API via the Metadata Proxy. We have an experimental implementation with
the Dragonflow Neutron plugin. In this case the VMs access the API at
169.254.169.254:80 and the Metadata Proxy distinguishes Tatu calls from Nova
metadata calls and proxies them to Tatu instead of Nova. In support of this
feature, Tatu's configuration has an api_endpoint_for_vms parameter in support
of this feature. The VM learns what IP address to use via Tatu's dynamic vendor
data.

Scope of user and host SSH certificates
---------------------------------------

User certificates are generated with a per-project User CA. Host certificates
are generated with a per-project Host CA.

An OpenStack user wishing to ssh into VMs belonging to different projects will
require one certificate per project.

In the future we will consider using per-domain User and Host CAs. 

Principals and Linux accounts
-----------------------------

When a user SSH certificate is created for a given project, the list of
principals is equal to the user's role assignments in Keystone. If any of the
user's role assignments are deleted, Tatu automatically revokes any of the
user's certificates whose principal lists contain that role name.

When a Linux VM is launched, Tatu sets up a user account for each of the roles
in the project at that time. As of March 2018, there is no support for sync-ing
the Linux user accounts in the VM with the project's roles if they change after
VM launch.

Tatu leaves root and non-root default users (e.g. fedora use on fedora
VMs) intact, including any authorized_keys files. As a result, OpenStack
KeyPairs continue to work as designed, which is useful for debugging Tatu or
having a fallback method to access the VMs.

Tatu's policy is that any role containing the word "admin" results in a user
account with sudo privileges. Note that because of this policy, an OpenStack
user may not have sudo privileges on VMs she herself launched.

Uber's pam-ussh module
----------------------

Thanks to the uber/pam-ussh integration sudo privilege is revoked as soon as
the VM learns that the user's certificate has been revoked. However,
uber/pam-ussh requires the client to run ssh-agent, ssh-add their key
(corresponding to their certificate) and launch ssh with the -A option.

This feature is enabled/disabled by setting pam_sudo to True/False in tatu's
configuration. When the feature is disabled, sudo access is not authenticated,
it's password-less (since we don't use passwords in our user account setup).

Bastion Management
------------------

Tatu aims to manage SSH bastions for OpenStack environments. This feature
would provide the following benefits:

* reduce operational burden for users that already manage bastions themselves.
* avoid assigning Floating IP addresses to VMs for sole purpose of SSH access.
* provide a single point of security policy enforcement, and especially one
  that is harder to tamper with. A user with access to an account with sudo
  privileges on a VM may be able to tamper with the VM's security but not with
  the bastion's. This can significantly increase security if all SSH access
  is required to go through bastions.

As of March 2018, Tatu **does not** yet support general bastion management.

However, Tatu has an experimental feature (off by default) to provide ssh
access to VMs via PAT (port address translation). PAT provides only some of the
previously mentioned benefits of bastions: it avoids assigning a FloatingIP
per VM, but it does not provide a single point of policy enforcement because
PAT always translates and forwards without checking certificates as a full SSH
proxy would. **PAT bastions are only supported by an experimental version
of Dragonflow Neutron plugin.** It works as follows:

* At setup time, Tatu reserves a configurable number of ports in the Public
  network. Their IP addresses are used for PAT. Dragonflow randomly assigns
  each PAT addresses to a different compute node. That compute node then acts
  as a "pat-bastion".
* Tatu also sets up DNS A records for each pat-bastion in OpenStack Designate.
  For example, if the bastion's address is 172.24.4.9, then the A record's URL
  will be "bastion-172-24-4-9.<configurable-domain>."
* When a VM is launched Tatu reserves a unique port on each of a configurable
  number of pat-bastions and sets up Dragonflow PAT entries so that each
  translates to the VM's private address and port 22 (or a configurable port).
* The user can learn what pat-bastion:port pairs have been assigned to a VM by
  using Tatu's *ssh host* CLI or "Compute->SSH->Hosts" panel in Horizon. At
  this point the user can already SSH to the pat-bastion's IP using ssh's -p
  option to pass the unique port. Dragonflow will take care of receiving the
  traffic at the compute node that owns that PAT address, and translating
  and forwarding the packets to the VM's private IP. If the compute node fails,
  Tatu will eventually re-assign the PAT address to a different compute. In the
  meantime, if we configured num_pat_bastions_per_server > 1, then the user
  can ssh to the same VM via an alternative pat-bastion:port pair.
* At VM launch time, Tatu also sets up a DNS SRV record for each
  pat-bastion:port pair assigned to the VM. For example, if the VM has been
  assigned 172.24.4.9:1000, then the SRV record's URL will be
  "_ssh._tcp.<hostname>.<project_name>.<configurable-domain>." and will point
  to port 1000 on the A record with URL
  "bastion-172-24-4-9.<configurable-domain>." These SRV records provide an
  alternative way for the user to discover the pat-bastion:port pairs assigned
  to the VM. Tatu also provides an ssh wrapper script (under
  tatu/scripts/srvssh) that does an SRV lookup in DNS, and then calls ssh
  with the -p option.

Future Work
-----------

* The option to delegate certificate generation to a 3rd party, so that Tatu
  does not need access to your project's CA private keys.
* Support OCSP (Online Certificate Status Protocol) as an alternative to using
  Certificate Revocation Lists.
* Automate periodic User and Host CA key rotation.
* APIs to control the mapping of Keystone roles to Linux accounts (including
  ones configured via cloud-init).
* APIs to control finer-grained SSH access per project.
* Full bastion support (as opposed to PAT bastions).
* Per-domain User and Host CAs (e.g. shared across projects in a domain).

Automated user key rotation is not required because the API already allows
generating new user certificates on demand.

Is automated server key rotation useful? Would yearly Host CA key rotation
make server key rotation redundant?
