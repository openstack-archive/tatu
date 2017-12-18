Prerequisites
-------------

Before you install and configure the tatu service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``tatu`` database:

     .. code-block:: none

        CREATE DATABASE tatu;

   * Grant proper access to the ``tatu`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON tatu.* TO 'tatu'@'localhost' \
          IDENTIFIED BY 'TATU_DBPASS';
        GRANT ALL PRIVILEGES ON tatu.* TO 'tatu'@'%' \
          IDENTIFIED BY 'TATU_DBPASS';

     Replace ``TATU_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``tatu`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt tatu

   * Add the ``admin`` role to the ``tatu`` user:

     .. code-block:: console

        $ openstack role add --project service --user tatu admin

   * Create the tatu service entities:

     .. code-block:: console

        $ openstack service create --name tatu --description "tatu" tatu

#. Create the tatu service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        tatu public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        tatu internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        tatu admin http://controller:XXXX/vY/%\(tenant_id\)s
