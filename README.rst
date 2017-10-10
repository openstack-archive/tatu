===================================
Tatu - OpenStack's SSH-as-a-Service
===================================

Named in honor of Tatu Ylönen, the inventor of SSH, Tatu is an OpenStack service that manages user and host certificates. Tatu can also start and manage bastion servers so that you don't have to (and you don't have to give every SSH server a public IP address).

Tatu uses Barbican to store two private keys per OpenStack project:

* a User CA (Certificate Authority) key is used to sign a user public key, thus creating an SSH client's user certificate.
* a Host CA key is used to sign the SSH server's public key, thus creating an SSH host certificate.

Tatu provides APIs that allows:

* OpenStack users to obtain a user SSH certificate (per project) for their public key, with permissions corresponding to their roles in the project)
* OpenStack VM (or bare metal) instances to obtain a host SSH certificate for their public key.

During negotiation of the SSH connection:

#. The server presents its host certificate.
#. The client checks the validity of the host certificate using a Host CA public key configured in its known_hosts file (config line starts with @cert-authority).
#. The client presents its client certificate.
#. The server checks the validity of the client certifiate using a User CA public key configured in sshd_config (TrustedUserCAKeys). The server also checks that the certificate has not been revoked (RevokedKeys in sshd_config).
#. The client certificate also contains a list of SSH principals, some of which the sshd_config may recognize as mapped to specific Linux accounts on the server (AuthorizedPrincipalsFile in sshd_config). The client is only allowed to login to those Linux accounts.

Use of host certificates prevents MITM (man in the middle) attacks. Without host certificates, users of SSH client software are presented with a message like this one when they first connect to an SSH server:

  | The authenticity of host '111.111.11.111 (111.111.11.111)' can't be established.
  | ECDSA key fingerprint is fd:fd:d4:f9:77:fe:73:84:e1:55:00:ad:d6:6d:22:fe.
  | Are you sure you want to continue connecting (yes/no)? yes

SSH servers only need to store the User CA public key (and revoked client certificates), not every client certificate. This is simpler, more secure and more manageable than today's common practice: putting the client public key in the SSH server's authorized_keys file.

API
---

Tatu's APIs support:

* Creation of a user SSH certificate based on a Keystone User and:

  * A KeyPair from the Compute API;
  * Or a public SSH key.

* Creation of new SSH private key, public key, and user certificate based on a Keystone User.
* Revocation of user certificates.
* Reading one or many user certificates issued for a project.
* Reading one or many revoked user certificates for a project.
* Creation of a host SSH certificate and authorized principals files based on a Project and its Roles.
* Reading Tatu's Bastion CA public key. Bastions present host SSH certificates signed by this CA, so users configure their SSH clients to trust Tatu's bastions by adding this public key to their known_hosts file.

Scope of user and host SSH certificates
---------------------------------------

User certificates are generated with a per-project User CA. Host certificates are generated with a per-project Host CA; and SSH servers have their TrustedUserCAKeys point to a file containing the public key of their project's User CA.

Therefore, a User will require multiple certificates (one per project) to SSH to servers in multiple projects (even in the same domain).

In the future we will consider using per-domain User and Host CAs. 

Principals and Linux accounts
-----------------------------

When the user SSH certificate is created for a Keystone User, its list of principals is determined as follows:

* If any of the User's Roles have a name containing "admin" (regardless of capitalization), add a principal with name "ProjectAdmin".
* Add a principal whose name is the User identity.

Tatu installs a file named "root" at the path indicated by AuthorizedPrincipalsFile entry in sshd_config. The file contains two lines:

  | ProjectAdmin
  | <Identity of instance owner>

Note that on platforms that have a non-root default user (usually with sudo privilege), the file will be named as that user. For example, on Ubuntu 16.04, the file will be named "ubuntu".

As a result, the following Users are able to login to an instance as root (or as the default user):

* The instance owner;
* Any User that has an "admin" Role (in the Domain).

In the future we will support non-root access and giving specific roles SSH access to specific sets of instances.

Bastion Management
------------------

Tatu automatically runs an SSH bastion for each OpenStack project. Each bastion consumes one Neutron port on the public network and therefore one public IPv4 and IPv6 address. If Designate is enabled, Tatu inserts an A record and an AAAA record with name "tatu-bastion.<project-name>.<domain>" and the appropriate IPv4/v6 public address.

A bastion has an interface on each of the Project's Neutron Networks. Therefore Tatu consumes one port on every Neutron network. This, combined with the bastion's interface on the public network, allows users to SSH to instances even when their Networks are not publicly routable.

Assuming the SSH client's known_hosts file has been configured with two @cert-authority lines, one containing the Bastion CA public key, the other containing the Project Host CA public key, a user can SSH to her instance as follows:

  | ssh -o ProxyCommand="ssh -W %h:%p <bastion IP or DNS name" <account-name>@<instance IP or hostname>

For example:

  | ssh -o ProxyCommand="ssh -W %h:%p 10.99.157.129" ubuntu@10.0.0.13

Future Work
-----------

* The option to delegate certificate generation to a 3rd party, so that Tatu does not need access to your project's CA private keys.
* Support OCSP (Online Certificate Status Protocol) as an alternative to using Certificate Revocation Lists.
* Automate periodic User and Host CA key rotation.
* APIs to control the mapping of Keystone roles to Linux accounts (including ones configured via cloud-init).
* APIs to control finer-grained SSH access per project.
* Allow the option of enabling the Bastion per Neutron Network - allow avoiding consuming the extra port.
* Per-domain User and Host CAs.

Automated user key rotation is not required because the API already allows generating new user certificates on demand.
Automated server key rotation is not required because the API already allows generating new host certificates on demand. Yearly Host CA key rotation should make server key rotation redundant. 
