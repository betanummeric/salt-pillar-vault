# -*- coding: utf-8 -*-
"""
Use Vault secrets as a Pillar source

Example Configuration
---------------------

The Vault server should be defined in the master config file with the
following options:

.. code-block:: yaml

    ext_pillar:
      - vault:
          url: https://vault:8200
          config: Local path or salt:// URL to secret configuration file
          token: Explicit token for token authentication
          token_file: File containing a Vault token to use
          role_id: Role ID for AppRole authentication
          secret_id: Explicit Secret ID for AppRole authentication
          secret_file: File to read for secret-id value
          unset_if_missing: Leave pillar key unset if Vault secret not found
          memcached_socket: Path to a unix socket, e.g. /var/run/memcached/memcached.sock
          memcached_expiration: Number of seconds to cache secrets for e.g. 60
          memcached_timeout: Number of seconds to wait before timing out e.g. 1

The ``url`` parameter is the full URL to the Vault API endpoint.

The ``config`` parameter is the path or salt:// URL to the secret map YML file.

The ``token`` parameter is an explicit token to use for authentication, and it
overrides all other authentication methods.

The ``token_file`` parameter is the path to a file containing a token, such
as output by Vault Agent.

The ``role_id`` parameter is a Role ID to use for AppRole authentication.

The ``secret_id`` parameter is an explicit Role ID to pair with ``role_id`` for
AppRole authentication.

The ``secret_file`` parameter is the path to a file on the master to read for a
``secret-id`` value if ``secret_id`` is not specified.

The ``unset_if_missing`` parameter determins behavior when the Vault secret is
missing or otherwise inaccessible. If set to ``True``, the pillar key is left
unset. If set to ``False``, the pillar key is set to ``None``. Default is
``False``

The ``memcached_socket`` parameter is the path to a unix socket on the master
to use for caching vault secrets.  Expiration of cached secrets defaults to
5 minutes.

The ``memcached_timeout`` parameter sets the memcache connection `timeout`
and `connect_timeout`.  Takes an integer number of seconds.

The ``memcached_expiration`` parameter specifies the number of seconds to
keep secrets cached in memcached before they must be fetched from Vault
again.  Defaults to 300 (5 minutes).

Mapping Vault Secrets to Minions
--------------------------------

The ``config`` parameter, above, is a path to the YML file which will be
used for mapping secrets to minions. The map uses syntax similar to the
top file:

.. code-block:: yaml

    'filter':
      'variable': 'path'
      'variable': 'path?key'
    'filter':
      'variable': 'path?key'


Each ``filter`` is a compound matcher:
    https://docs.saltstack.com/en/latest/topics/targeting/compound.html

``variable`` is the name of the variable which will be injected into the
pillar data.

``path`` is the path the desired secret on the Vault server.

``key`` is optional. If specified, only this specific key will be returned
for the secret at ``path``. If unspecified, the entire secret json structure
will be returned.


.. code-block:: yaml

    'web*':
      'ssl_cert': '/secret/certs/domain?certificate'
      'ssl_key': '/secret/certs/domain?private_key'
    'db* and G@os.Ubuntu':
      'db_pass': '/secret/passwords/database

"""

# Import stock modules
from __future__ import absolute_import
import base64
import logging
import os
import yaml

# Import salt modules
import salt.loader
import salt.minion
import salt.template
import salt.utils.minions

# Attempt to import the 'hvac' module
try:
    import hvac
    HAS_HVAC = True
except ImportError:
    HAS_HVAC = False

# Get pymemcache
try:
    from pymemcache.client.base import Client as memclient
    MEMCACHE_CAPABLE = True
except ImportError:
    MEMCACHE_CAPABLE = False

# Set up logging
LOG = logging.getLogger(__name__)

# Default config values
CONF = {
    'url': 'https://vault:8200',
    'config': '/srv/salt/secrets.yml',
    'token': None,
    'token_file': None,
    'role_id': None,
    'secret_id': None,
    'secret_file': None,
    'unset_if_missing': False,
    'memcached_socket': None,
    'memcached_timeout': 1,
    'memcached_expiration': 300
}

def __virtual__():
    """ Only return if hvac is installed
    """
    if HAS_HVAC:
        return True
    else:
        LOG.error("Vault pillar requires the 'hvac' python module")
        return False


def _get_id_from_file(source="/.vault-id"):
    """ Reads a UUID from file (default: /.vault-id)
    """
    source = os.path.abspath(os.path.expanduser(source))
    LOG.debug("Reading '%s' for uuid", source)

    uuid = ""

    # pylint: disable=invalid-name
    if os.path.isfile(source):
        with open(source, "r") as fd:
            uuid = fd.read()

    return uuid.strip()


def _authenticate(conn):
    """ Determine the appropriate authentication method and authenticate
        for a token, if necesssary.
    """

    # Check for explicit token, first
    if CONF["token"]:
        conn.token = CONF["token"]

    # Check for token file, such as output by Vault Agent
    elif CONF["token_file"]:
        token = _get_id_from_file(CONF["token_file"])
        conn.token = token

    # Check for explicit AppRole authentication
    elif CONF["role_id"]:
        if CONF["secret_id"]:
            secret_id = CONF["secret_id"]
        elif CONF["secret_file"]:
            secret_id = _get_id_from_file(source=CONF["secret_file"])
        else:
            secret_id = _get_id_from_file()

        # Perform AppRole authentication
        result = conn.auth_approle(CONF["role_id"], secret_id)
        # Required until https://github.com/ianunruh/hvac/pull/90
        # is merged, due in hvac 0.3.0
        conn.token = result['auth']['client_token']

    # Check for token in ENV
    elif os.environ.get('VAULT_TOKEN'):
        conn.token = os.environ.get('VAULT_TOKEN')


def fetch(vault_conn, mem_conn, location, expire_seconds=300,
        unset_if_missing=False):
    """Takes a location in Vault and connection to Vault + optionally memcache.

    Args:
        vault_conn: hvac.Client connection object that has been
                    pre-authenticated.
        mem_conn: pymemcache connection object or None.
        location: string path of Vault key with '?' delimiter between path
                  and desired field.
    Returns: Requested secret as a string.
    """
    if mem_conn:
        secret = mem_conn.get(location)
        if secret is not None:
            LOG.debug("Get cached value for '%s'", location)
            return secret
    try:
        (path, key) = location.split('?', 1)
    except ValueError:
        (path, key) = (location, None)
    secret = vault_conn.read(path)
    if key:
        secret = secret["data"].get(key, None)
        prefix = "base64:"
        if secret and secret.startswith(prefix):
            secret = base64.b64decode(secret[len(prefix):]).rstrip()
    if secret or not unset_if_missing:
        if mem_conn:
            LOG.debug("Set cached value for '%s'", location)
            mem_conn.set(location, secret, expire=expire_seconds)
        return secret


def ext_pillar(minion_id, pillar, *args, **kwargs):
    """ Main handler. Compile pillar data for the specified minion ID
    """
    vault_pillar = pillar

    # Load configuration values
    for key in CONF:
        if kwargs.get(key, None):
            CONF[key] = kwargs.get(key)

    # Determine whether to enable secret caching
    if MEMCACHE_CAPABLE and CONF['memcached_socket']:
        memcache_enabled = True
    else:
        memcache_enabled = False

    # Resolve salt:// fileserver path, if necessary
    if CONF["config"].startswith("salt://"):
        local_opts = __opts__.copy()
        local_opts["file_client"] = "local"
        minion = salt.minion.MasterMinion(local_opts)
        CONF["config"] = minion.functions["cp.cache_file"](CONF["config"])

    # Read the secret map
    renderers = salt.loader.render(__opts__, __salt__)
    raw_yml = salt.template.compile_template(CONF["config"], renderers, 'jinja', whitelist=[], blacklist=[])
    if raw_yml:
        secret_map = yaml.safe_load(raw_yml.getvalue()) or {}
    else:
        LOG.error("Unable to read secret mappings file '%s'", CONF["config"])
        return vault_pillar

    if not CONF["url"]:
        LOG.error("'url' must be specified for Vault configuration")
        return vault_pillar

    # Create a memcached connection if configured
    if memcache_enabled:
        LOG.info("Starting memcached connection for secrets pillar")
        mem_conn = memclient(
            CONF['memcached_socket'],
            connect_timeout=CONF['memcached_timeout'],
            timeout=CONF['memcached_timeout'])
    else:
        LOG.info("Skipping memcached connection")
        mem_conn = None

    # Connect and authenticate to Vault
    conn = hvac.Client(url=CONF["url"])
    _authenticate(conn)

    # Apply the compound filters to determine which secrets to expose for this minion
    ckminions = salt.utils.minions.CkMinions(__opts__)
    for fltr, secrets in secret_map.items():
        minions =  ckminions.check_minions(fltr, "compound")
        if 'minions' in minions:
            # In Salt 2018 this is now in a kwarg
            minions = minions['minions']
        if minion_id in minions:
            for variable, location in secrets.items():
                value = fetch(conn,
                              mem_conn,
                              location,
                              expire_seconds=CONF['memcached_expiration'],
                              unset_if_missing=CONF['unset_if_missing'])
                if value:
                    vault_pillar[variable] = value

    if memcache_enabled:
        mem_conn.close()

    return vault_pillar
