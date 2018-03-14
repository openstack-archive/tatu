Notes on using Tatu for the first time
======================================

**In this example, I'm the "demo" user and I need to connect to VMs in projects
named "demo" and "invisible_to_admin".**

Generate SSH keys and certificates
----------------------------------

Since you'll need separate SSH user certificates for each of your projects,
generate separate ssh keys for each of your projects::

    ssh-keygen -f ~/.ssh/demo_key
    ssh-keygen -f ~/.ssh/inv_key

Now generate the certificate for each of your projects (this can also be done in
Horizon). First set your environment variables to select your user and project.
Note that ssh client expects the certificate's name to be the private key name
followed by "-cert.pub"::

    source /opt/stack/devstack/openrc demo demo
    openstack ssh usercert create -f value -c Certificate "`cat ~/.ssh/demo_key.pub`" > ~/.ssh/demo_key-cert.pub
    openstack ssh usercert create --os-project-name invisible_to_admin -f value -c Certificate "`cat ~/.ssh/inv_key.pub`" > ~/.ssh/inv_key-cert.pub

You can examine a certificate as follows::

    ssh-keygen -Lf ~/.ssh/inv_key-cert.pub

And the output will look like this::

    /root/.ssh/inv_key-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:4h+zwW8L+E1OLyOz4uHh4ffcqJFS/p5rETlf15Q04x8
        Signing CA: RSA SHA256:s8FpsDHkhly3ePtKDihO/x7UVj3sw3fSILLPLQJz2n0
        Key ID: "demo_5"
        Serial: 5
        Valid: from 2018-03-09T13:05:23 to 2019-03-10T13:05:23
        Principals:
                Member
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc

Note that the Signing CA is different for each certificate. You'll have to use
the corresponding key/certificate to ssh to a project's VM.

Configure your client to trust the Certificate Authority for hosts
------------------------------------------------------------------

Now configure your ssh client to trust SSH host certificats signed by the Host
CAs of your projects. Given how Tatu currently generates Host certificates,
you must trust each project's Host CA for hostnames in any domain (hence the
"*" in the command)::

    demo_id=`openstack project show demo -f value -c id`
    echo '@cert-authority * '`openstack ssh ca show $demo_id -f value -c 'Host Public Key'` >> ~/.ssh/known_hosts
    inv_id=`openstack project show invisible_to_admin --os-project-name invisible_to_admin -f value -c id`
    echo '@cert-authority * '`openstack ssh ca show $inv_id -f value -c 'Host Public Key'` >> ~/.ssh/known_hosts

Above, note that the --os-project-name option is necessary because we sourced
openrc with the "demo" project.

Your known_hosts file should now have one @cert-authority line for each project::

    cat ~/.ssh/known_hosts
        @cert-authority * ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...
        @cert-authority * ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKVCfrfD...

Launch your VM
--------------

Now launch a VM without a Key Pair. Unless you're using Dragonflow and Tatu's
experimental PAT bastion feature, assign a floating IP to the VM. In this example
we'll assume the VM's Floating IP is 172.24.4.8

**Make sure to launch your VM on a private network that has a router attached,
and that the router has a gateway.** In other words, unless you're using a
bastion, the VM's IP must be routable via the Floating IP.

If you look in Tatu API's log, you should see something like the following.
There may be several calls to /v1/novavendordata because Nova queries Tatu
once for each version of Nova metadata API. It's OK, Tatu returns the same
data each time. The call to /noauth/hostcerts is the VM's request to Tatu to
generate an SSH host certificate. The call does not use Keystone authentication
but is protected by the one-time-token presented in "token_id"::

    journalctl --unit devstack@tatu-api.service
      Request POST /v1/novavendordata with body {... u'hostname': u'fluffy', u'boot-roles': u'admin,Member,anotherrole', u'image-id': ... u'project-id': ... u'instance-id': ...}
        produced response with status 201 Created location /hosttokens/489b555621f74494adf7089174563bfb
        and body {"api_endpoint": "http://172.24.4.1:18322", "auth_pub_key_user": ... "token": "489b555621f74494adf7089174563bfb", "root_principals": "",
                  "ssh_port": 2222, "sudoers": "admin", "pam_sudo": true, "users": "admin,Member,anotherrole"}
      ...
      Request POST /noauth/hostcerts with body {u'token_id': '489b555621f74494adf7089174563bfb', u'pub_key': ... u'host_id': ...}
        produced response with status 200 OK location /hostcerts/717f9144e20e408380e174bda5855b3b/MD5:da:08:6f:d9:cc:b9:57:66:cb:b7:50:7f:d1:26:71:26
        and body {"created_at": "2018-03-14T18:27:58.000000", "hostname": "fluffy", "expires_at": "2019-03-14T18:27:58.000000", "cert": ...

SSH to your VM
--------------

If you launched your VM in the demo project, use the following ssh command. Note
that the Linux user account must correspond to one of the principals in your
certificate, which in turn corresponds to one of your roles in the project::

    ssh -i ~/.ssh/demo_key Member@172.24.4.8

Thanks to the host's SSH certificate and the @cert-authority line in the client's
known_hosts file, a man-in-the-middle (MITM) attack risk is eliminated, so
**you should no longer see this warning that you always ignore**::

    The authenticity of host '172.24.4.8 (172.24.4.8)' can't be established.
    RSA key fingerprint is SHA256:FS2QGF4Ant/MHoUPxgO6N99uQss57lKkPclXDgFOLAU.
    Are you sure you want to continue connecting (yes/no)?

Re-run the command with verbose output::

    ssh -v -i ~/.ssh/demo_key Member@172.24.4.8

You should see the SSH host presenting its host certificate::

    debug1: Server host certificate: ssh-rsa-cert-v01@openssh.com SHA256:FS2QGF4Ant/MHoUPxgO6N99uQss57lKkPclXDgFOLAU, serial 0 ID "otto_0" CA ssh-rsa SHA256:b0BD63oM4ks4BT2Cxlzz9WaV0HE+AqwEG7mnk3vJtz4 valid from 2018-03-09T04:32:35 to 2019-03-10T04:32:35
    debug1: Host '172.24.4.8' is known and matches the RSA-CERT host certificate.
    debug1: Found CA key in /root/.ssh/known_hosts:1

You should also see your SSH client presenting your user certificate. Note that your
client first offers the public key, which is rejected, and then offers the certificate,
which is accepted::

    debug1: Next authentication method: publickey
    debug1: Offering RSA public key: /root/.ssh/inv_key
    debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic
    debug1: Offering RSA-CERT public key: /root/.ssh/inv_key-cert
    debug1: Server accepts key: pkalg ssh-rsa-cert-v01@openssh.com blen 1088

Sudo privileges
---------------

Tatu's convention is that every Keystone role associated with a project should
have a corresponding Linux user account on the VM. In addition, any role with
'admin' in its name should have a user account with sudo privileges.

When tatu's configuration key "pam_sudo" is set to False, then sudo calls are
allowed without authentication. Tatu creates a file 130-admin in /etc/sudoers.d
and containing this configuration::

    admin ALL= NOPASSWD: ALL

In order to test this, go to Horizon, Identity->Projects and click on "Manage
Members" for one of your projects. Now give one of your Keystone users the role
'admin'. You will have to generate a new SSH user certificate. You may also
need to launch a new VM if none of the project's users previously had an admin
role (because Tatu does not currently keep the VM's accounts up to date with
the project's Keystone roles).


Using Uber's pam-ussh module
----------------------------

Uber's pam-ussh module handles authentication of sudo calls. You can enable it
by setting "pam_sudo = True" in the "tatu" stanza in /etc/tatu/tatu.conf.

Tatu's conventions about sudo privileges (explained in the previous section)
still apply, so go ahead and give one of your project's users a role with
'admin' in its name. Then launch a VM.

Uber's pam-ussh authenticates sudo calls by querying the client's SSH agent.
You'll need to run ssh-agent, set some environment variables and ssh-add your
private key::

    ssh-agent
        SSH_AUTH_SOCK=/tmp/ssh-IrDH7qOuujNe/agent.17084; export SSH_AUTH_SOCK;
        SSH_AGENT_PID=17085; export SSH_AGENT_PID;
        echo Agent pid 17085;
    # Set the environment variables by copy/pasting the previous command's output
    SSH_AUTH_SOCK=/tmp/ssh-IrDH7qOuujNe/agent.17084; export SSH_AUTH_SOCK;
    # Add your private key to the agent
    ssh-add ~/.ssh/demo_key
    ssh-add -l
        2048 SHA256:obvWOMbOuQyaqpvUI9+YxZiNCItlAL3JsQsZEEEx/6k /root/.ssh/demo_key (RSA)
        2048 SHA256:obvWOMbOuQyaqpvUI9+YxZiNCItlAL3JsQsZEEEx/6k /root/.ssh/demo_key (RSA-CERT)

When you launch ssh, **remember to enable agent forwarding with the -A option**,
otherwise pam-ussh won't be able to query your agent. We won't need the -i
option now because the agent will take care of trying the appropriate keys and
certificates in its negotiation with the server. But let's use the -v option so
we can see when pam-ussh does its authentication::

    ssh -v -A admin@172.24.4.8
        ...
        debug1: Requesting authentication agent forwarding.
        ...
        Last login: Tue Mar 13 04:33:05 2018 from 172.24.4.1
    [admin@dusty ~]$ sudo echo hello
        debug1: client_input_channel_open: ctype auth-agent@openssh.com rchan 2 win 65536 max 16384
        debug1: channel 1: new [authentication agent connection]
        debug1: confirm auth-agent@openssh.com
      hello
        debug1: channel 1: FORCE input drain
        debug1: channel 1: free: authentication agent connection, nchannels 2
    [admin@dusty ~]$ sudo echo how are you
      how are you
    [admin@dusty ~]$

What just happened? Afer login, the first time we ran sudo, there was another
exchange between ssh server and client. Pam-ussh uses the agent AUTH_SOCK on
the server to query the ssh-client for its certificates. The ssh-client gets
them from the ssh-agent. Pam-ussh tries to find a valid ssh certificate (that
has NOT been revoked - it should not be in the revoked-keys file on the server).
Failing that, pam-ussh will give up and pass the torch to another pam module
that does password-based authentication.

How did Tatu configure this on the VM? For each user that should be granted
sudo privileges, Tatu created a file named like 130-admin in /etc/sudoers.d.
Its contents look like this::

    admin ALL= ALL
    Defaults:admin timestamp_timeout=1

A few things to note:

* Compared to when pam_sudo is false, the "NOPASSWD:" option has been dropped;
* sudo is set to re-authenticate every 1 minute (thanks to timestamp_timeout)
  and that's why the second sudo call above didn't re-authenticate (unless you
  waited 60 seconds).

Finally, take a look at the PAM configuration::

    [admin@dusty ~]$ cat /etc/pam.d/sudo
      #%PAM-1.0
      auth sufficient /lib64/security/pam_ussh.so ca_file=/etc/ssh/ca_user.pub authorized_principals=admin revoked_keys_file=/etc/ssh/revoked-keys
      auth       include      system-auth
      account    include      system-auth
      password   include      system-auth
      session    optional     pam_keyinit.so revoke
      session    required     pam_limits.so
      session    include      system-auth

Note that pam_ussh validation alone is sufficient to achieve validation. It's
important that pam_ussh is placed before system-auth. If it were after, pam
modules in system-auth would be called first and the user would have to fail
to enter their password a few times before certificate-based authentication
was attempted by pam_ussh.

Pam-ush's parameters specifies that only 'admin' account can authenticate with
SSH certificates (others will have to use default mechanism, i.e. passwords,
which Tatu does not provide); also, pam-ussh will check the revoked-keys file
that Tatu's VM scripts are keeping up-to-date; and finally, certificate
signatures are checked against the User CA public key stored in ca_user.pub
