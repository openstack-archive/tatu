===================================================
Note on configuring CA domains in known_hosts file.
===================================================

As of March 2018, Tatu requires writing the Host CA public key (of each project
whose VMs' host certificates you want to trust) in the known_hosts file as:

  | @cert-authority * <ca-public-key>

The '*' represents the SSH hosts' hostname domain for which the client wants
to trust the CA.

Note also that Tatu currently generates host certificates with Key ID set to
host's name e.g. "berry" (without FQDN, like "berry.<project>.<domain>").
The hostname is passed with the -I option to the call to ssh-keygen -h -s...
to generate the host certificate.

We could tighten up the @cert-authority line like this:

  | @cert-authority *.demo.ssh.pino.com <ca-public-key>

by passing the hosts's fully qualified name to ssh-keygen. However, the ssh
client would only accept the host certificate if the ssh command was launched
with the SSH server's fully qualified name (as opposed to IP address). In other
words, this would work:

  | ssh <account-name>@berry.demo.ssh.pino.com

while this would not (the client would reject the certificate):

  | ssh <account-name>@<ip address>

...unless a reverse DNS lookup (PTR record lookup) for that IP address returns
the host's fully qualified name in demo.ssh.pino.com domain. Tatu does not
currently set up DNS PTR records, but this should be possible via Designate.
But keep in mind that the ip addresses might be those of bastions rather than
VMs.

TODO: validate these ideas.