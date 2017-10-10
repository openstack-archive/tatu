============
Architecture
============

Tatu consists of the following components:

* An API server
* An external Nova VendorData [1] REST service (ssh-vd)
* An API proxy
* A bastion coordinator
* The SSH bastion

API
---

The API server signs user and host SSH public keys (for both compute instances and bastions) and returns certificates. It depends on Barbican to store the private keys of the User and Host CAs (Certificate Authorities, per project) and the Bastion CA.

ssh-vd
------

**ssh-vd** is the key component in installing an instance's host SSH certificate. There are two possible approaches:

#. Generate private key, public key and host certificate off the instance, then install them on the instance.
#. Generate keys off the instance, then transfer the public key to the SSHaaS API to generate the host certificate, then install them on the instance.

We cannot automate the first approach in OpenStack (up to Pike release) because MetaData is not secure [2] and (for now) we're avoiding changes to Nova. We therefore use the second approach. Specifically:

#. Configure Nova dynamic vendor data to call ssh-vd, which returns a one-time token to use with the main API. Nova makes it available both via the MetaData API and via ConfigDrive (if your cloud uses that).
#. Pass a cloud-init script (i.e. cloud-config) to the instance via static Nova vendor data.
#. The cloud-init script calls the main SSHaaS API, passing the instance's host public key and the one-time-token.
#. The API uses the one-time token to decide which hostname, which project, and then generate and return the host SSH certificate.
#. The cloud-init script installs the host certificate and configures SSHD to use it.

Note that there is a race-condition whereby malicious code could discover the one-time-token via MetaData API and attempt to generate a host SSH certificate for its own public key. To be successful, the attacker would also have to divert client SSH connection to its own instance.

A proper fix requires securing MetaData API or hinting which data is too senstive for MetaData API (and should only be offered to the instance via Config Drive). For now we live with the race condition and add code in both the instance (cloud-init) and SSHaaS API to indicate whether the one-time-token was used twice with different public keys.

API Proxy
---------

The instance must itself participate in SSH certificate management because:

* in the approach we took with ssh-vd, the instance calls an API to have its public key signed;
* future immprovements will require instances to fetch Certificate Revocation Lists, exchange OCSP (Online Certificate Status Protocol) messages, update User CA key and change host certificate (when the User and Host CA keys are rotated.

The SSH API must be accessible to the instance even when its Neutron network is isolated. We therefore follow the approach of MetaData, i.e. we offer a SSH API Proxy at a well-known link-local address. Communication with this Proxy API does not need to be secured (i.e. can use http rather than https) in that sensitive data is not transmitted (the host public key from the instance to the API, then the host certificate from the API to the instance).

However, if securing the API Proxy is preferred, this is easy to do: static or dynamic vendor data could be used to pass the API Proxy's X.509 certificate to the instance. This allows using https and prevents a DOS attack whereby a MITM (man-in-the-middle) signs the host certificate with the wrong host key.

Bastion Coordinator
-------------------

This component launches Bastion code in a container or VM, allocates the required Neutron ports and (re)configures the Bastion instances with interfaces on appropriate networks. It also (re)configures user accounts and SSHD as necessary within the Bastion.

The bastion coordinator stores database records for each bastion it manages.

The bastion coordinator itself must be redundant. This is not yet the case. When the bastion starts it recomputes the desired configuration for all bastions and then synchronizes with the actual state.

Bastion
-------

The coordinator restarts bastions that fail (reside on failing hosts). The check is only done periodically (on the order of a few minutes). In the future, the bastion should offer a meaningful health check and a fast-failure detection and recovery.

Depending on the size of the project (number of Users and instances, amount of data to transfer over SSH) it may be useful for the Bastion (with a single public IP) to be composed of multiple virtual bastions. This requires sticky load-balancing (á la Maglev [3]) to work properly, otherwise upstream routing changes would break SSH connections. For now, each bastion is implemented as a single VM or container.

References
----------

#. https://docs.openstack.org/nova/latest/user/vendordata.html
#. https://wiki.openstack.org/wiki/OSSN/OSSN-0074
#. https://research.google.com/pubs/pub44824.html
