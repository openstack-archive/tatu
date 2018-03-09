================
Jump Proxy Notes
================

**NOTE: This feature is NOT YET IMPLEMENTED.**

Assuming the SSH client's known_hosts file has been configured with two
@cert-authority lines (one containing the Bastion CA public key, the other
containing the Project Host CA public key), a user can SSH to her instance as
follows:

  | ssh -o ProxyCommand="ssh -W %h:%p <bastion IP or DNS name" <account-name>@<instance IP or hostname>

For example:

  | ssh -o ProxyCommand="ssh -W %h:%p 10.99.157.129" ubuntu@10.0.0.13

Or (for OpenSSH 7.3 and later):

  | ssh -o ProxyJump="10.99.157.129" ubuntu@10.0.0.13

Note that one of the user SSH certificate's principals must be mapped to an
account on the bastion (or the bastion will reject the SSH connection). Tatu
should configure the bastion (e.g. on Ubuntu 16.04) AuthorizedPrincipalFile
with a single file named 'nobody' which contains the names of all principals.
This allows the SSH client to use the bastion as a jump host but not to login
there; this secures the bastion itself. The ssh command is therefore:

  | ssh -o ProxyJump="nobody@10.99.157.129" ubuntu@10.0.0.13
