This directory contains the Tatu (SSH-as-a-Service) DevStack plugin.

To configure Tatu with DevStack, you will need to enable this plugin and
the Tatu service by adding one line to the [[local|localrc]] section of
your local.conf file.

To enable the plugin, add a line of the form:

    enable_plugin tatu <GITURL> [GITREF]

where

    <GITURL> is the URL of a Tatu repository
    [GITREF] is an optional git ref (branch/ref/tag).  The default is master.

For example

    enable_plugin tatu https://github.com/pinodeca/tatu stable/queens

For more information, see the "Externally Hosted Plugins" section of
https://docs.openstack.org/devstack/latest/plugins.html