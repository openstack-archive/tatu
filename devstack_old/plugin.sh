# plugin.sh - DevStack plugin.sh dispatch script

function install_tatu {
    ...
}

function init_tatu {
    ...
}

function configure_tatu {
    ...
}

# check for service enabled
if is_service_enabled tatu; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services tatu"

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing tatu"
        install_tatu

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring tatu"
        configure_tatu

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the tatu service
        echo_summary "Initializing tatu"
        init_tatu
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down tatu services
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        :
    fi
fi