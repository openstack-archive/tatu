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

    # Override the logging_context_format_string value chosen by
    # setup_colorized_logging.
    iniset $conf_file $conf_section logging_context_format_string "%(asctime)s.%(msecs)03d %(color)s%(levelname)s %(name)s [[01;36m%(request_id)s [00;36m%(user_identity)s%(color)s] [01;35m%(instance)s%(color)s%(message)s[00m"
}

# DevStack Plugin
# ---------------

# cleanup_tatu - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_tatu {
    sudo rm -rf $TATU_STATE_PATH $TATU_AUTH_CACHE_DIR
    cleanup_tatu_backend
}

# configure_tatu - Set config files, create data dirs, etc
function configure_tatu {
    [ ! -d $TATU_CONF_DIR ] && sudo mkdir -m 755 -p $TATU_CONF_DIR
    sudo chown $STACK_USER $TATU_CONF_DIR

    [ ! -d $TATU_LOG_DIR ] &&  sudo mkdir -m 755 -p $TATU_LOG_DIR
    sudo chown $STACK_USER $TATU_LOG_DIR

    # (Re)create ``tatu.conf``
    rm -f $TATU_CONF

    # General Configuration
    iniset_rpc_backend tatu $TATU_CONF DEFAULT
    iniset $TATU_CONF DEFAULT rpc_response_timeout 5

    iniset $TATU_CONF DEFAULT debug $ENABLE_DEBUG_LOG_LEVEL
    iniset $TATU_CONF DEFAULT state_path $TATU_STATE_PATH
    iniset $TATU_CONF DEFAULT root-helper sudo tatu-rootwrap $TATU_ROOTWRAP_CONF
    iniset $TATU_CONF storage:sqlalchemy connection `database_connection_url tatu`

    # API Configuration
    sudo cp $TATU_DIR/etc/tatu/api-paste.ini $TATU_APIPASTE_CONF
    iniset $TATU_CONF service:api api_base_uri $TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT/

    # Root Wrap
    sudo cp $TATU_DIR/etc/tatu/rootwrap.conf.sample $TATU_ROOTWRAP_CONF
    iniset $TATU_ROOTWRAP_CONF DEFAULT filters_path $TATU_DIR/etc/tatu/rootwrap.d root-helper

    # Oslo Concurrency
    iniset $TATU_CONF oslo_concurrency lock_path "$TATU_STATE_PATH"

    # Set up the rootwrap sudoers for tatu
    local rootwrap_sudoer_cmd="$TATU_BIN_DIR/tatu-rootwrap $TATU_ROOTWRAP_CONF *"
    local tempfile=`mktemp`
    echo "$STACK_USER ALL=(root) NOPASSWD: $rootwrap_sudoer_cmd" >$tempfile
    chmod 0440 $tempfile
    sudo chown root:root $tempfile
    sudo mv $tempfile /etc/sudoers.d/tatu-rootwrap

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

    # Backend Plugin Configuation
    configure_tatu_backend
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

    # Init and migrate tatu database
    tatu-manage database sync

    init_tatu_backend
}

# install_tatu - Collect source and prepare
function install_tatu {
    if is_ubuntu; then
        install_package libcap2-bin
    elif is_fedora; then
        # bind-utils package provides `dig`
        install_package libcap bind-utils
    fi

    git_clone $TATU_REPO $TATU_DIR $TATU_BRANCH
    setup_develop $TATU_DIR

    install_tatu_backend
}

# install_tatuclient - Collect source and prepare
function install_tatuclient {
    if use_library_from_git "python-tatuclient"; then
        git_clone_by_name "python-tatuclient"
        setup_dev_lib "python-tatuclient"
    else
        pip_install_gr "python-tatuclient"
    fi
}

# install_tatudashboard - Collect source and prepare
function install_tatudashboard {
    git_clone_by_name "tatu-dashboard"
    setup_dev_lib "tatu-dashboard"

    for panel in _3980_tatu_panel_group.py \
                 _3981_tatu_ca_panel.py \
                 _3982_tatu_user_panel.py \
                 _3983_tatu_host_panel.py; do
        ln -fs $TATUDASHBOARD_DIR/tatudashboard/enabled/$panel $HORIZON_DIR/openstack_dashboard/local/enabled/$panel
    done
}

# start_tatu - Start running processes
function start_tatu {
    start_tatu_backend

    run_process tatu-central "$TATU_BIN_DIR/tatu-central --config-file $TATU_CONF"
    run_process tatu-api "$TATU_BIN_DIR/tatu-api --config-file $TATU_CONF"

    # Start proxies if enabled
    if is_service_enabled tatu-api && is_service_enabled tls-proxy; then
        start_tls_proxy tatu-api '*' $TATU_SERVICE_PORT $TATU_SERVICE_HOST $TATU_SERVICE_PORT_INT &
    fi

    if ! timeout $SERVICE_TIMEOUT sh -c "while ! wget --no-proxy -q -O- $TATU_SERVICE_PROTOCOL://$TATU_SERVICE_HOST:$TATU_SERVICE_PORT; do sleep 1; done"; then
        die $LINENO "Tatu did not start"
    fi
}

# stop_tatu - Stop running processes
function stop_tatu {
    stop_process tatu-central
    stop_process tatu-api

    stop_tatu_backend
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
