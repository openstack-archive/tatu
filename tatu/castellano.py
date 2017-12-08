from castellan.common.objects.passphrase import Passphrase
from castellan.common.utils import credential_factory
from castellan.key_manager import API
from castellan.key_manager.key_manager import KeyManager
from castellan.options import set_defaults as set_castellan_defaults
from oslo_config import cfg

opts = [
    cfg.BoolOpt('use_barbican_key_manager', default=False,
                help='Enable the usage of the OpenStack Key Management '
                     'service provided by barbican.'),
]

CONF = cfg.CONF
CONF.register_opts(opts, group='tatu')
_context = None
_api = None

def validate_config():
    if CONF.tatu.use_barbican_key_manager:
        set_castellan_defaults(CONF)
    else:
        set_castellan_defaults(CONF,
                               api_class='tatu.castellano.TatuKeyManager')

def context():
    global _context
    if _context is None and CONF.tatu.use_barbican_key_manager:
        _context = credential_factory(conf=CONF)
    return _context

def api():
    global _api
    if _api is None:
        _api = API()
    return _api 

def delete_secret(id, ctx=None):
    """delete a secret from the external key manager
    :param id: The identifier of the secret to delete
    :param ctx: The context, and associated authentication, to use with
                this operation (defaults to the current context)
    """
    api().delete(ctx or context(), id)

def get_secret(id, ctx=None):
    """get a secret associated with an id
    :param id: The identifier of the secret to retrieve
    :param ctx: The context, and associated authentication, to use with
                this operation (defaults to the current context)
    """
    key = api().get(ctx or context(), id)
    return key.get_encoded()

def store_secret(secret, ctx=None):
    """store a secret and return its identifier
    :param secret: The secret to store, this should be a string
    :param ctx: The context, and associated authentication, to use with
                this operation (defaults to the current context)
    """
    key = Passphrase(secret)
    return api().store(ctx or context(), key)

"""
This module contains the KeyManager class that will be used by the
castellan library, it is not meant for direct usage within tatu.
"""
class TatuKeyManager(KeyManager):
    """Tatu specific key manager
    This manager is a thin wrapper around the secret being stored. It is
    intended for backward compatible use only. It will not store keys
    or generate UUIDs but instead return the secret that is being stored.
    This behavior allows Tatu to continue storing secrets in its database
    while using the Castellan key manager abstraction.
    """
    def __init__(self, configuration=None):
        pass

    def create_key(self, context, algorithm=None, length=0,
                   expiration=None, **kwargs):
        pass

    def create_key_pair(self, *args, **kwargs):
        pass

    def store(self, context, key, expiration=None, **kwargs):
        """store a key
        in normal usage a store_key will return the UUID of the key as
        dictated by the key manager. Tatu would then store this UUID in
        its database to use for retrieval. As tatu is not actually using
        a key manager in this context it will return the key's payload for
        storage.
        """
        return key.get_encoded()

    def get(self, context, key_id, **kwargs):
        """get a key
        since tatu is not actually storing key UUIDs the key_id to this
        function should actually be the key payload. this function will
        simply return a new TatuKey based on that value.
        """
        return Passphrase(passphrase=key_id)

    def delete(self, context, key_id, **kwargs):
        """delete a key
        as there is no external key manager, this function will not
        perform any external actions. therefore, it won't change anything.
        """
        pass
