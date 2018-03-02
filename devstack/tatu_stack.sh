#!/bin/bash

# **tatu_stack.sh**

# ``tatu_stack.sh`` is meant to run after devstack's stack.sh and stacks only Tatu.
# - it must be run from the openstack-dev/devstack directory as the stack user.

# OpenStack is designed to be run as a non-root user; Horizon will fail to run
# as **root** since Apache will not serve content from **root** user).
# ``stack.sh`` must not be run as **root**.  It aborts and suggests one course of
# action to create a suitable user account.

set -o xtrace

unset GREP_OPTIONS

unset LANG
unset LANGUAGE
LC_ALL=en_US.utf8
export LC_ALL

# Make sure umask is sane
umask 022

# Not all distros have sbin in PATH for regular users.
PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin

# Keep track of the DevStack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)

# Check for uninitialized variables, a big cause of bugs
NOUNSET=${NOUNSET:-}
if [[ -n "$NOUNSET" ]]; then
    set -o nounset
fi

# ``stack.sh`` keeps the list of ``deb`` and ``rpm`` dependencies, config
# templates and other useful files in the ``files`` subdirectory
FILES=$TOP_DIR/files
if [ ! -d $FILES ]; then
    die $LINENO "missing devstack/files"
fi

# ``stack.sh`` keeps function libraries here
# Make sure ``$TOP_DIR/inc`` directory is present
if [ ! -d $TOP_DIR/inc ]; then
    die $LINENO "missing devstack/inc"
fi

# ``stack.sh`` keeps project libraries here
# Make sure ``$TOP_DIR/lib`` directory is present
if [ ! -d $TOP_DIR/lib ]; then
    die $LINENO "missing devstack/lib"
fi

if [[ "${POSIXLY_CORRECT}" == "y" ]]; then
    set +o xtrace
    echo "You are running POSIX compatibility mode, DevStack requires bash 4.2 or newer."
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    set +o xtrace
    echo "DevStack should be run as a user with sudo permissions, "
    echo "not root."
    echo "A \"stack\" user configured correctly can be created with:"
    echo " $TOP_DIR/tools/create-stack-user.sh"
    exit 1
fi

# Initialize variables:
LAST_SPINNER_PID=""

# Import common functions
source $TOP_DIR/functions

# Import config functions
source $TOP_DIR/inc/meta-config

# Import 'public' stack.sh functions
source $TOP_DIR/lib/stack

# Determine what system we are running on.  This provides ``os_VENDOR``,
# ``os_RELEASE``, ``os_PACKAGE``, ``os_CODENAME``
# and ``DISTRO``
GetDistro

# Phase: local
rm -f $TOP_DIR/.localrc.auto
extract_localrc_section $TOP_DIR/local.conf $TOP_DIR/localrc $TOP_DIR/.localrc.auto

if [[ ! -r $TOP_DIR/stackrc ]]; then
    die $LINENO "missing $TOP_DIR/stackrc - did you grab more than just stack.sh?"
fi

source $TOP_DIR/stackrc
source $TOP_DIR/openrc admin admin

export_proxy_variables

disable_negated_services

# Destination path for installation ``DEST``
DEST=${DEST:-/opt/stack}

# Destination path for service data
DATA_DIR=${DATA_DIR:-${DEST}/data}

LOCAL_HOSTNAME=`hostname -s`

VERBOSE=$(trueorfalse True VERBOSE)
VERBOSE_NO_TIMESTAMP=$(trueorfalse False VERBOSE)

TIMESTAMP_FORMAT=${TIMESTAMP_FORMAT:-"%F-%H%M%S"}
LOGDAYS=${LOGDAYS:-7}
CURRENT_LOG_TIME=$(date "+$TIMESTAMP_FORMAT")

if [[ true ]]; then
    # Set up output redirection without log files
    # Set fd 3 to a copy of stdout. So we can set fd 1 without losing
    # stdout later.
    exec 3>&1
    if [[ "$VERBOSE" != "True" ]]; then
        # Throw away stdout and stderr
        exec 1>/dev/null 2>&1
    fi
    # Always send summary fd to original stdout
    exec 6> >( $TOP_DIR/tools/outfilter.py -v >&3 )
fi

# Basic test for ``$DEST`` path permissions (fatal on error unless skipped)
check_path_perm_sanity ${DEST}

# Print the kernel version
uname -a

SSL_BUNDLE_FILE="$DATA_DIR/ca-bundle.pem"

# Import common services (database, message queue) configuration
source $TOP_DIR/lib/database
source $TOP_DIR/lib/rpc_backend

# Configure Projects
# ==================

# Clone all external plugins
fetch_plugins

# Plugin Phase 0: override_defaults - allow plugins to override
# defaults before other services are run
run_phase override_defaults

# Import Apache functions
source $TOP_DIR/lib/apache

# Import TLS functions
source $TOP_DIR/lib/tls

# Source project function libraries
source $TOP_DIR/lib/infra
source $TOP_DIR/lib/libraries
source $TOP_DIR/lib/lvm
source $TOP_DIR/lib/horizon
source $TOP_DIR/lib/keystone
source $TOP_DIR/lib/glance
source $TOP_DIR/lib/nova
source $TOP_DIR/lib/placement
source $TOP_DIR/lib/cinder
source $TOP_DIR/lib/swift
source $TOP_DIR/lib/neutron
source $TOP_DIR/lib/ldap
source $TOP_DIR/lib/dstat
source $TOP_DIR/lib/etcd3

# Extras Source
# --------------

# Phase: source
run_phase source

initialize_database_backends && echo "Using $DATABASE_TYPE database backend" || echo "No database enabled"

source $DEST/tatu/devstack/settings
source $DEST/tatu/devstack/plugin.sh stack pre-install
source $DEST/tatu/devstack/plugin.sh stack install
source $DEST/tatu/devstack/plugin.sh stack post-config
source $DEST/tatu/devstack/plugin.sh stack extra
source $DEST/tatu/devstack/plugin.sh stack test-config
