Notes on using Tatu for the first time
======================================

If you don't already have one, generate an ssh key pair on your client machine.

    ssh-keygen

Now generate a certificate for your public key (this can also be done in
Horizon). First set your environment variables to select your user and project.

    source openrc demo demo
    openstack ssh usercert create -f value -c Certificate "`cat ~/.ssh/id_rsa.pub`" > ~/.ssh/id_rsa-cert.pub

Now get the host CA public key for your project. This command appends the key
to your known_hosts file and configures it to be trusted for any hostname in
any domain.

    echo '@cert-authority * ' `openstack ssh ca show 626bfa8fd12b48d8b674caf4ef3a0cd7 -f value -c 'Host Public Key'` >> ~/.ssh/known_hosts

Now launch a VM without a Key Pair. Unless you're using Dragonflow and Tatu's
experimental PAT bastion feature, assign a floating IP to the VM, for example
172.24.4.10.

Use the following to 
