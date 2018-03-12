# Install and start **Tatu** service in Devstack

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

# Helper Functions
# ----------------
function setup_colorized_logging_tatu {
    local conf_file=$1
    local conf_section=$2
    local project_var=${3:-"project_name"}
    local user_var=${4:-"user_name"}

    setup_colorized_logging $conf_file $conf_section $project_var $user_var
}

# DevStack Plugin
# ---------------

# cleanup_tatu - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_tatu {
    sudo rm -rf $TATU_STATE_PATH $TATU_AUTH_CACHE_DIR
}

# configure_tatu - Set config files, create data dirs, etc
function configure_tatu {
    [ ! -d $TATU_CONF_DIR ] && sudo mkdir -m 755 -p $TATU_CONF_DIR
    sudo chown $STACK_USER $TATU_CONF_DIR

    [ ! -d $TATU_LOG_DIR ] &&  sudo mkdir -m 755 -p $TATU_LOG_DIR
    sudo chown $STACK_USER $TATU_LOG_DIR

    # (Re)create ``tatu.conf``
    rm -f $TATU_CONF

    local admin_project
    admin_project=$(openstack project show "admin" -f value -c id)
    local admin_user
    admin_user=$(openstack user show "admin" -f value -c id)

    iniset $TATU_CONF tatu auth_url $KEYSTONE_SERVICE_URI/v3
    iniset $TATU_CONF tatu user_id $admin_user
    iniset $TATU_CONF tatu password $ADMIN_PASSWORD
    iniset $TATU_CONF tatu project_id $admin_project 
    iniset $TATU_CONF tatu use_barbican $TATU_USE_BARBICAN
    iniset $TATU_CONF tatu use_pat_bastions $TATU_USE_PAT_BASTIONS
    iniset $TATU_CONF tatu ssh_port 2222
    iniset $TATU_CONF tatu num_total_pats $TATU_NUM_TOTAL_PATS
    iniset $TATU_CONF tatu num_pat_bastions_per_server $TATU_PAT_BASTIONS_PER_SERVER
    iniset $TATU_CONF tatu pat_dns_zone_name $TATU_DNS_ZONE_NAME
    iniset $TATU_CONF tatu pat_dns_zone_email $TATU_DNS_ZONE_EMAIL
    iniset $TATU_CONF tatu sqlalchemy_engine `database_connection_url tatu`
    iniset $TATU_CONF tatu api_endpoint_for_vms $TATU_API_FOR_VMS
    iniset $TATU_CONF tatu pam_sudo True

    # Need Keystone and Nova notifications
    iniset $KEYSTONE_CONF oslo_messaging_notifications topics notifications,tatu_notifications
    iniset $NOVA_CONF oslo_messaging_notifications topics notifications,tatu_notifications

    iniset $NOVA_CONF DEFAULT force_config_drive TRUE

    # Set up Tatu static vendor data.
    $TATU_DIR/scripts/cloud-config-to-vendor-data $TATU_DIR/files/user-cloud-config > $NOVA_CONF_DIR/tatu_static_vd.json
    iniset $NOVA_CONF api vendordata_providers StaticJSON,DynamicJSON
    iniset $NOVA_CONF api vendordata_jsonfile_path $NOVA_CONF_DIR/tatu_static_vd.json
    iniset $NOVA_CONF api vendordata_dynamic_targets tatu@$TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT/novavendordata
    iniset $NOVA_CONF api vendordata_dynamic_connect_timeout 5
    iniset $NOVA_CONF api vendordata_dynamic_read_timeout 30
    iniset $NOVA_CONF vendordata_dynamic_auth auth_url $KEYSTONE_SERVICE_URI
    iniset $NOVA_CONF vendordata_dynamic_auth auth_type password
    iniset $NOVA_CONF vendordata_dynamic_auth username admin
    iniset $NOVA_CONF vendordata_dynamic_auth password $ADMIN_PASSWORD
    iniset $NOVA_CONF vendordata_dynamic_auth project_id $admin_project
    iniset $NOVA_CONF vendordata_dynamic_auth user_domain_name default

    # Castellan (Barbican client) credentials
    iniset $TATU_CONF key_manager auth_url $KEYSTONE_SERVICE_URI
    iniset $TATU_CONF key_manager auth_type keystone_password
    iniset $TATU_CONF key_manager user_id $admin_user
    iniset $TATU_CONF key_manager password $ADMIN_PASSWORD
    iniset $TATU_CONF key_manager project_id $admin_project

    # General Configuration
    iniset_rpc_backend tatu $TATU_CONF DEFAULT
    iniset $TATU_CONF DEFAULT rpc_response_timeout 5

    iniset $TATU_CONF DEFAULT debug $ENABLE_DEBUG_LOG_LEVEL
    iniset $TATU_CONF DEFAULT state_path $TATU_STATE_PATH
    iniset $TATU_CONF storage:sqlalchemy connection `database_connection_url tatu`

    # API Configuration
    sudo cp $TATU_DIR/etc/tatu/api-paste.ini $TATU_APIPASTE_CONF
    iniset $TATU_CONF service:api api_base_uri $TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT/

    # Oslo Concurrency
    iniset $TATU_CONF oslo_concurrency lock_path "$TATU_STATE_PATH"

    # TLS Proxy Configuration
    if is_service_enabled tls-proxy; then
        # Set the service port for a proxy to take the original
        iniset $TATU_CONF service:api listen ${TATU_SERVICE_HOST}:${TATU_SERVICE_PORT_INT}
    else
        iniset $TATU_CONF service:api listen ${TATU_SERVICE_HOST}:${TATU_SERVICE_PORT}
    fi

    # Setup the Keystone Integration
    if is_service_enabled keystone; then
        iniset $TATU_CONF service:api auth_strategy keystone
        configure_auth_token_middleware $TATU_CONF tatu $TATU_AUTH_CACHE_DIR
    fi

    # Logging Configuration
    if [ "$SYSLOG" != "False" ]; then
        iniset $TATU_CONF DEFAULT use_syslog True
    fi

    # Format logging
    if [ "$LOG_COLOR" == "True" ] && [ "$SYSLOG" == "False" ]; then
        setup_colorized_logging_tatu $TATU_CONF DEFAULT "tenant" "user"
    fi
}

function configure_tatudashboard {
    # Compile message catalogs
    if [ -d ${TATUDASHBOARD_DIR}/tatudashboard/locale ]; then
        (cd ${TATUDASHBOARD_DIR}/tatudashboard; DJANGO_SETTINGS_MODULE=openstack_dashboard.settings ../manage.py compilemessages)
    fi
}

# create_tatu_accounts - Set up common required tatu accounts

# Tenant               User       Roles
# ------------------------------------------------------------------
# service              tatu       admin        # if enabled
function create_tatu_accounts {
    if is_service_enabled tatu-api; then
        create_service_user "tatu"

        get_or_create_service "tatu" "ssh" "Tatu SSH Service"
        get_or_create_endpoint "ssh" \
            "$REGION_NAME" \
            "$TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT/"
    fi
}

# init_tatu - Initialize etc.
function init_tatu {
    # Create cache dir
    sudo mkdir -p $TATU_AUTH_CACHE_DIR
    sudo chown $STACK_USER $TATU_AUTH_CACHE_DIR
    rm -f $TATU_AUTH_CACHE_DIR/*

    # (Re)create tatu database
    recreate_database tatu utf8
}

# install_tatu - Collect source and prepare
function install_tatu {
    git_clone $TATU_REPO $TATU_DIR $TATU_BRANCH
    setup_develop $TATU_DIR
}

# install_tatuclient - Collect source and prepare
function install_tatuclient {
    git_clone_by_name "python-tatuclient"
    setup_dev_lib "python-tatuclient"
}

# install_tatudashboard - Collect source and prepare
function install_tatudashboard {
    git_clone_by_name "tatu-dashboard"
    setup_dev_lib "tatu-dashboard"

    for panel in _3980_tatu_panel_group.py \
                 _3981_tatu_ca_panel.py \
                 _3982_tatu_user_panel.py \
                 _3983_tatu_host_panel.py \
                 _3984_tatu_pat_panel.py \
                 _3985_tatu_host_cert_panel.py; do
        ln -fs $TATUDASHBOARD_DIR/tatudashboard/enabled/$panel $HORIZON_DIR/openstack_dashboard/local/enabled/$panel
    done
}

# start_tatu - Start running processes
function start_tatu {
    local PSERVE=`which pserve`
    run_process tatu-api "$PSERVE $TATU_APIPASTE_CONF"
    local PYTHON=`which python`
    run_process tatu-agent "$PYTHON $TATU_DIR/tatu/notifications.py"

    # Start proxies if enabled
    if is_service_enabled tatu-api && is_service_enabled tls-proxy; then
        start_tls_proxy tatu-api '*' $TATU_SERVICE_PORT $TATU_SERVICE_HOST $TATU_SERVICE_PORT_INT &
    fi

    local wget_cmd
    wget_cmd="wget --no-proxy -q -O- $TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT/noauth"
    echo waiting on $wget_cmd
    if ! timeout $SERVICE_TIMEOUT sh -c "until $wget_cmd; do sleep 1; echo re-trying; done"; then
        die $LINENO "Tatu did not start"
    fi
}

# stop_tatu - Stop running processes
function stop_tatu {
    stop_process tatu-api
    stop_process tatu-agent
}

# This is the main for plugin.sh
if is_service_enabled tatu; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Tatu client"
        install_tatuclient

        echo_summary "Installing Tatu"
        install_tatu

        if is_service_enabled horizon; then
            echo_summary "Installing Tatu dashboard"
            install_tatudashboard
        fi

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring Tatu"
        configure_tatu
        if is_service_enabled horizon; then
            echo_summary "Configuring Tatu dashboard"
            configure_tatudashboard
        fi

        if is_service_enabled keystone; then
            echo_summary "Creating Tatu Keystone accounts"
            create_tatu_accounts
        fi

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing Tatu"
        init_tatu

        echo_summary "Starting Tatu"
        start_tatu
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_tatu
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Cleaning Tatu"
        cleanup_tatu
    fi
fi

# Restore xtrace
$XTRACE
