Notes on using Tatu for the first time
======================================

**In this example, I'm the "demo" user and I need to connect to VMs in projects
named "demo" and "invisible_to_admin".**

**In the following examples, openstack commands will output a warning like this**::

    Failed to contact the endpoint at http://147.75.65.211:18322/ for discovery. Fallback to using that endpoint as the base url.

**You can safely ignore this warning.**

Since you'll need separate SSH user certificates for each of your projects,
generate separate ssh keys for each of your projects::

    ssh-keygen -f ~/.ssh/demo_key
    ssh-keygen -f ~/.ssh/inv_key

Now generate the certificate for each of your projects (this can also be done in
Horizon). First set your environment variables to select your user and project.
Note that ssh client expects the certificate's name to be the private key name
followed by "-cert.pub"::

    source openrc demo demo
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

Now configure your ssh client to trust SSH host certificats signed by the Host
CAs of your projects. Given how Tatu currently generates Host certificates,
you must trust each CA for hostnames in any domain (hence the "*" in the command)::

    demo_id=`openstack project show demo -f value -c id`
    echo '@cert-authority * '`openstack ssh ca show $demo_id -f value -c 'Host Public Key'` >> ~/.ssh/known_hosts
    inv_id=`openstack project show invisible_to_admin --os-project-name invisible_to_admin -f value -c id`
    echo '@cert-authority * '`openstack ssh ca show $inv_id -f value -c 'Host Public Key'` >> ~/.ssh/known_hosts

Above, note that the --os-project-name option is necessary because we sourced
openrc with the "demo" project.

Now launch a VM without a Key Pair. Unless you're using Dragonflow and Tatu's
experimental PAT bastion feature, assign a floating IP to the VM. In this example
we'll assume the VM's Floating IP is 172.24.4.8

If you launched your VM in the demo project, use the following ssh command. Note
that the Linux user account must correspond to one of the principals in your
certificate, which in turn corresponds to one of your roles in the project::

    ssh -i ~/.ssh/demo_key Member@172.24.4.8

** You should not get a warning like the following**::

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
