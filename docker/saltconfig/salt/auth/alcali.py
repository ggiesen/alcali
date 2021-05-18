# -*- coding: utf-8 -*-

"""
Alcali authentication.

Provide authentication using either MySQL or Postgres.
Use Returner database connection settings.

Enable Alcali authentication.

.. code-block:: yaml

    external_auth:
      alcali:
        matt:
          - test.*

:depends:   - MySQL-python Python module or psycopg2.
"""

from __future__ import absolute_import
import logging
import sys
from contextlib import contextmanager

# Import 3rd-party libs
import salt.exceptions
import salt.ext.six as six

log = logging.getLogger(__name__)

try:
    import MySQLdb

    HAS_MYSQL = True
except ImportError:
    HAS_MYSQL = False

try:
    import psycopg2

    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

__virtualname__ = "alcali"


def __virtual__():
    if HAS_MYSQL or HAS_POSTGRES:
        return __virtualname__
    return False


def _get_options():
    """
    Returns options used for the database connection.
    """

    _options = {}
    defaults = {
        "host": "salt",
        "user": "salt",
        "pass": "salt",
        "db": "salt",
        "port": 3306,
        "ssl_ca": None,
        "ssl_cert": None,
        "ssl_key": None,
    }

    if HAS_MYSQL:
        for k, v in six.iteritems(defaults):
            try:
                _options[k] = __opts__["{}.{}".format("mysql", k)]
            except KeyError:
                _options[k] = v
    else:
        # Use "returner.postgres" options.
        defaults.pop("pass")
        defaults["passwd"] = "salt"
        defaults["port"] = 5432
        for k, v in six.iteritems(defaults):
            try:
                _options[k] = __opts__["{}.{}".format("returner.postgres", k)]
            except KeyError:
                _options[k] = v

    # post processing
    for k, v in six.iteritems(_options):
        if isinstance(v, six.string_types) and v.lower() == "none":
            # Ensure 'None' is rendered as None
            _options[k] = None
        if k == "port":
            # Ensure port is an int
            _options[k] = int(v)

    return _options


@contextmanager
def _get_serv():
    """
    Return a database cursor
    """
    _options = _get_options()

    log.debug("Generating new DB connection pool")
    if HAS_MYSQL:
        try:
            # An empty ssl_options dictionary passed to MySQLdb.connect will
            # effectively connect w/o SSL.
            ssl_options = {}
            if _options.get("ssl_ca"):
                ssl_options["ca"] = _options.get("ssl_ca")
            if _options.get("ssl_cert"):
                ssl_options["cert"] = _options.get("ssl_cert")
            if _options.get("ssl_key"):
                ssl_options["key"] = _options.get("ssl_key")
            conn = MySQLdb.connect(
                host=_options.get("host"),
                user=_options.get("user"),
                passwd=_options.get("pass"),
                db=_options.get("db"),
                port=_options.get("port"),
                ssl=ssl_options,
            )

        except MySQLdb.connections.OperationalError as exc:
            raise salt.exceptions.SaltMasterError(
                "MySQL returner could not connect to database: {exc}".format(exc=exc)
            )

        cursor = conn.cursor()

        try:
            yield cursor
        except MySQLdb.DatabaseError as err:
            error = err.args
            sys.stderr.write(str(error))
            raise err
    else:
        try:
            conn = psycopg2.connect(
                host=_options.get("host"),
                user=_options.get("user"),
                password=_options.get("passwd"),
                database=_options.get("db"),
                port=_options.get("port"),
            )

        except psycopg2.OperationalError as exc:
            raise salt.exceptions.SaltMasterError(
                "postgres returner could not connect to database: {exc}".format(exc=exc)
            )

        cursor = conn.cursor()

        try:
            yield cursor
        except psycopg2.DatabaseError as err:
            error = err.args
            sys.stderr.write(str(error))
            raise err
        finally:
            conn.close()


def auth(username, password):
    """
    Authenticate using a MySQL/PostgreSQL user table
    """

    log.debug("Alcali attempting to authenticate user '{}'".format(username))
    if str(password) and str(password) != "REVOKED":
        with _get_serv() as cur:
            sql = """SELECT c.token FROM user_settings c INNER JOIN auth_user a ON c.user_id = a.id AND a.username= %s;"""
            cur.execute(sql, (username,))

            user_token = cur.fetchone()
            if user_token:
                token = str(user_token[0])
                if str(token) == str(password):
                    log.debug("Alcali successfully authenticated user: '{}'".format(username))
                    return True
    return False


def groups(username, **kwargs):
    """
    Retrieve group membership using a MySQL/PostgreSQL user table
    """

    log.debug("Alcali attempting to fetch groups for user '{}'".format(username))
    with _get_serv() as cur:
        sql = """SELECT a.name FROM auth_user c INNER JOIN auth_user_groups b ON c.id = b.user_id INNER JOIN auth_group a ON b.group_id = a.id AND c.username = %s;"""
        cur.execute(sql, (username,))
        groups_result = cur.fetchall()
        if groups_result:
            groups = []
            for row in groups_result:
                for column in row:
                    groups.append(column)
            log.debug("Alcali successfully fetched groups for user '{}': {}".format(username, groups))
            return groups
    return []
