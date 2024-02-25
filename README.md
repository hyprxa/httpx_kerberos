HTTPX Kerberos/GSSAPI Authentication Library
===============================================

HTTPX is a fully featured HTTP client library for Python 3. This library
adds optional Kerberos/GSSAPI authentication support and supports mutual
authentication. Basic GET usage:

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth
    >>> r = httpx.get("http://example.org", auth=HTTPKerberosAuth())
    ...

Setup
-----

On Windows, no additional setup is required. The package will use SSPI and select
the Kerberos SSP under the hood.

In order to use this library on Linux, there must already be a Kerberos Ticket-Granting
Ticket(TGT) cached in a Kerberos credential cache. Whether a TGT is available
can be easily determined by running the ``klist`` command. If no TGT is
available, then it first must be obtained by running the ``kinit`` command, or
pointing the $KRB5CCNAME to a credential cache with a valid TGT.

In short, the library will handle the "negotiations" of Kerberos authentication,
but ensuring that an initial TGT is available and valid is the responsibility
of the user.

Authentication Failures
-----------------------

Client authentication failures will be communicated to the caller by returning
the 401 response. A 401 response may also come from an expired Ticket-Granting
Ticket.

Mutual Authentication
---------------------

### REQUIRED

By default, ``HTTPKerberosAuth`` will require mutual authentication from the
server, and if a server emits a non-error response which cannot be
authenticated, a ``httpx_kerberos.errors.MutualAuthenticationError`` will
be raised. If a server emits an error which cannot be authenticated, it will
be returned to the user but with its contents and headers stripped. If the
response content is more important than the need for mutual auth on errors,
(eg, for certain WinRM calls) the stripping behavior can be suppressed by
setting ``sanitize_mutual_error_response=False``:

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth, MutualAuthentication
    >>> kerberos_auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.REQUIRED, sanitize_mutual_error_response=False)
    >>> r = httpx.get("https://windows.example.org/wsman", auth=kerberos_auth)
    ...

### OPTIONAL

If you'd prefer to not require mutual authentication, you can set your
preference when constructing your ``HTTPKerberosAuth`` object:

.. code-block:: python

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth, MutualAuthentication
    >>> kerberos_auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.OPTIONAL)
    >>> r = httpx.get("http://example.org", auth=kerberos_auth)
    ...

This will cause ``httpx_kerberos`` to attempt mutual authentication if the
server advertises that it supports it, and cause a failure if authentication
fails, but not if the server does not support it at all.

### DISABLED

While we don't recommend it, if you'd prefer to never attempt mutual
authentication, you can do that as well:

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth, MutualAuthentication
    >>> kerberos_auth = HTTPKerberosAuth(mutual_authentication=MutualAuthentication.DISABLED)
    >>> r = httpx.get("http://example.org", auth=kerberos_auth)
    ...

Hostname Override
-----------------

If communicating with a host whose DNS name doesn't match its
kerberos hostname (eg, behind a content switch or load balancer),
the hostname used for the Kerberos GSS exchange can be overridden by
setting the ``hostname_override`` arg:

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth
    >>> kerberos_auth = HTTPKerberosAuth(hostname_override="internalhost.local")
    >>> r = httpx.get("https://externalhost.example.org/", auth=kerberos_auth)
    ...

Explicit Principal
------------------

``HTTPKerberosAuth`` normally uses the default principal (ie, the user for
whom you last ran ``kinit`` or ``kswitch``, or an SSO credential if
applicable). However, an explicit principal can be specified, which will
cause Kerberos to look for a matching credential cache for the named user.
This feature depends on OS support for collection-type credential caches,
as well as working principal support in PyKerberos (it is broken in many
builds). An explicit principal can be specified with the ``principal`` arg:

.. code-block:: python

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth
    >>> kerberos_auth = HTTPKerberosAuth(principal="user@REALM")
    >>> r = httpx.get("http://example.org", auth=kerberos_auth)
    ...

On Windows, WinKerberos is used instead of PyKerberos. WinKerberos allows the
use of arbitrary principals instead of a credential cache. Passwords can be
specified by following the form ``user@realm:password`` for ``principal``.

Delegation
----------

``httpx_kerberos`` supports credential delegation (``GSS_C_DELEG_FLAG``).
To enable delegation of credentials to a server that requests delegation, pass
``delegate=True`` to ``HTTPKerberosAuth``:

.. code-block:: python

    >>> import httpx
    >>> from httpx_kerberos import HTTPKerberosAuth
    >>> r = httpx.get("http://example.org", auth=HTTPKerberosAuth(delegate=True))
    ...

Be careful to only allow delegation to servers you trust as they will be able
to impersonate you using the delegated credentials.

Logging
-------

This library makes extensive use of Python's logging facilities.

Log messages are logged to the ``kerberos`` named logger.

If you are having difficulty we suggest you configure logging. Issues with the
underlying kerberos libraries will be made apparent. Additionally, copious debug
information is made available which may assist in troubleshooting if you
increase your log level all the way up to debug.

Channel Binding
---------------

This library automatically attempts to bind the
authentication token with the channel binding data when connecting over a TLS
connection. Channel Binding is also known as Extended Protection for
Authentication (``EPA``) from Microsoft. This should be ignored by servers
which do not implement support for CB but in the rare case this still fails it
can be disabled by setting ``send_cbt=False``.
