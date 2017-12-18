2. Edit the ``/etc/tatu/tatu.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://tatu:TATU_DBPASS@controller/tatu
