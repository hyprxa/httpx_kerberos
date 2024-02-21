from __future__ import annotations

import base64
import logging
import re
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Dict, TYPE_CHECKING

import spnego
import spnego.channel_bindings
import spnego.exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm
from httpx import Auth, Cookies, Headers

from httpx_kerberos.exceptions import (
    KerberosExchangeError,
    KerberosUnsupported,
    MutualAuthenticationError,
    NegotiationStepFailedWarning,
    NoCertificateRetrievedWarning,
    UnknownSignatureAlgorithmOID,
)

if TYPE_CHECKING:
    from collections.abc import Generator
    from httpx import Request, Response


_LOGGER = logging.getLogger("kerberos")
_cached_certs: Dict[str, CachedCert] = {}
_pattern = re.compile(r"Negotiate\s*([^,]*)", re.I)


@dataclass(slots=True, frozen=True)
class CachedCert:
    cert: x509.Certificate
    application_data: bytes

    @property
    def expired(self) -> bool:
        return datetime.now(tz=timezone.utc) >= self.cert.not_valid_after_utc


class MutualAuthentication(IntEnum):
    REQUIRED = 1
    OPTIONAL = 2
    DISABLED = 3


def sanitize_response(response: Response) -> None:
    """Sanitize the headers and content for a response.

    This is only used for HTTP Error messages which do not support mutual
    authentication when mutual authentication is required.

    Manipulates the response object in place because we cannot send back a new
    response object to the client in HTTPX auth flow.
    """
    inherit_headers = {
        k: response.headers[k] for k in ("date", "server") if k in response.headers
    }
    response.headers = Headers(headers=inherit_headers)
    response.headers["content-length"] = "0"
    response._cookies = Cookies()
    response._content = b""
    response.is_stream_consumed = True


def format_auth_header(auth_header: str | None) -> str | None:
    """Limit length of authorization header to 75 characters."""
    if auth_header is not None and len(auth_header) > 75:
        return auth_header[:48] + "..." + auth_header[-24:]


def negotiate_value(response: Response) -> bytes | None:
    """Extracts the gssapi authentication token from the appropriate header"""
    authreq = response.headers.get("www-authenticate", None)

    if authreq:
        match_obj = _pattern.search(authreq)
        if match_obj:
            return base64.b64decode(match_obj.group(1))


def get_certificate_hash(
    cert: x509.Certificate, certificate_der: bytes
) -> bytes | None:
    # https://tools.ietf.org/html/rfc5929#section-4.1
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm as e:
        warnings.warn(
            "Failed to get signature algorithm from certificate, "
            f"unable to pass channel bindings: {str(e)}",
            UnknownSignatureAlgorithmOID,
        )
        return None

    assert hash_algorithm is not None, "Unexpected type for hash algorithm."
    # if the cert signature algorithm is either md5 or sha1 then use sha256
    # otherwise use the signature algorithm
    if hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256(), default_backend())
    else:
        digest = hashes.Hash(hash_algorithm, default_backend())

    digest.update(certificate_der)
    certificate_hash = digest.finalize()

    return certificate_hash


def get_channel_bindings_application_data(response: Response) -> tuple[x509.Certificate, bytes] | tuple[None, None]:
    """https://tools.ietf.org/html/rfc5929 4. The 'tls-server-end-point' Channel
    Binding Type.

    Gets the application_data value for the 'tls-server-end-point' CBT Type.
    This is ultimately the SHA256 hash of the certificate of the HTTPS endpoint
    appended onto ``"tls-server-end-point"``. This value is then passed along to the
    kerberos library to bind to the auth response. If the socket is not an SSL
    socket or the raw HTTP object is not a urllib3 HTTPResponse then `None` will
    be returned and the Kerberos auth will use GSS_C_NO_CHANNEL_BINDINGS.
    """
    scheme = response.url.scheme.lower()
    host = response.url.host
    port = response.url.port
    if not port:
        port = 443 if scheme == "https" else 80
    if scheme != "https":
        return None, None

    _LOGGER.debug("Retrieving SSL certificate at %s:%i", host, port)
    try:
        certificate_pem = ssl.get_server_certificate((host, port))
    except ssl.SSLError:
        _LOGGER.warning(
            "Failed to retrieve SSL certificate at %s:%i", host, port, exc_info=True
        )
        warnings.warn(
            f"Unable to retrieve SSL certificate at {host}:{port}",
            NoCertificateRetrievedWarning,
        )
        return None, None

    certificate_der = ssl.PEM_cert_to_DER_cert(certificate_pem)
    cert = x509.load_der_x509_certificate(certificate_der, default_backend())
    certificate_hash = get_certificate_hash(cert, certificate_der)
    if certificate_hash is not None:
        application_data = b"tls-server-end-point:" + certificate_hash
        return cert, application_data
    
    return None, None


class HTTPKerberosAuth(Auth):
    """Generates the HTTP GSSAPI/Kerberos Authentication header for a request."""

    def __init__(
        self,
        mutual_authentication: int = MutualAuthentication.REQUIRED,
        service: str = "HTTP",
        delegate: bool = False,
        principal: str | None = None,
        hostname_override: str | None = None,
        sanitize_mutual_error_response: bool = True,
        send_cbt: bool = True,
    ):
        self._context: dict[str, spnego.ContextProxy] = {}
        self.mutual_authentication = MutualAuthentication(mutual_authentication)
        self.delegate = delegate
        self.pos = None
        self.service = service
        self.principal = principal
        self.hostname_override = hostname_override
        self.sanitize_mutual_error_response = sanitize_mutual_error_response
        self.auth_done = False

        # set the CBT values populated after the first response
        self.send_cbt = send_cbt
        self._cbts: dict[str, spnego.channel_bindings.GssChannelBindings | None] = {}

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        """Execute the kerberos auth flow."""
        # send the initial request
        response = yield request
        if response.status_code != 401:
            self.handle_other(response)
            return

        # check if we have already tried to get the CBT data value
        if self.send_cbt:
            scheme = request.url.scheme.lower()
            host = request.url.host
            port = request.url.port
            if not port:
                port = 443 if scheme == "https" else 80
            
            cached_cert = _cached_certs.get(host)
            if cached_cert is not None and not cached_cert.expired:
                _LOGGER.debug("Cached cert hit at %s:%i", host, port)
                assert host in self._cbts
            elif cached_cert is not None and cached_cert.expired:
                _LOGGER.info(
                    "Discarding cached SSL certificate at %s:%i. Certificate is expired",
                    host,
                    port,
                )
                assert host in self._cbts
                _cached_certs.pop(host)
                self._cbts.pop(host)
            
            if host not in self._cbts:
                cert, application_data = get_channel_bindings_application_data(response)
                if cert:
                    assert application_data
                    cached_cert = CachedCert(cert, application_data)
                    _cached_certs[host] = cached_cert
                    self._cbts[host] = spnego.channel_bindings.GssChannelBindings(
                        application_data=application_data,
                    )
                else:
                    assert not application_data
                    # store None so we don't waste time next time
                    self._cbts[host] = None

        try:
            # generate the authorization header
            self.handle_auth_error(request, response)
        except KerberosUnsupported:
            return

        response = yield request

        if response.status_code != 401:
            # authentication succeeded presumably
            self.handle_other(response)
        return

    def handle_auth_error(self, request: Request, response: Response) -> None:
        """Handles 401's, attempts to use gssapi/kerberos authentication"""

        _LOGGER.debug("Handling %i", response.status_code)
        if negotiate_value(response) is not None:
            self.authenticate_user(request, response)
        else:
            _LOGGER.debug("Kerberos is not supported, returning %r", response)
            raise KerberosUnsupported()

    def handle_other(self, response: Response) -> None:
        """Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested.
        """
        _LOGGER.debug("Handling %i", response.status_code)
        if (
            self.mutual_authentication
            in (MutualAuthentication.REQUIRED, MutualAuthentication.OPTIONAL)
            and not self.auth_done
        ):
            is_http_error = response.status_code >= 400
            if negotiate_value(response) is not None:
                _LOGGER.debug("Authenticating the server")
                if not self.authenticate_server(response):
                    # mutual authentication failure when mutual auth is wanted,
                    # raise an exception so the user doesn't use an untrusted
                    # response
                    _LOGGER.error("Mutual authentication failed")
                    raise MutualAuthenticationError(
                        f"Unable to authenticate {repr(response)}", response=response
                    )

                # authentication successful
                self.auth_done = True
                _LOGGER.debug("Mutual authentication succeeded, returning %r", response)
                return
            elif (
                is_http_error
                or self.mutual_authentication == MutualAuthentication.OPTIONAL
            ):
                if not response.is_success:
                    _LOGGER.error(
                        "Mutual authentication unavailable on %i response",
                        response.status_code,
                    )

                if (
                    self.mutual_authentication == MutualAuthentication.REQUIRED
                    and self.sanitize_mutual_error_response
                ):
                    sanitize_response(response)
                    return
                return
            else:
                # unable to attempt mutual authentication when mutual auth is
                # required, raise an exception so the user doesn't use an
                # untrusted response
                _LOGGER.error("Mutual authentication failed")
                raise MutualAuthenticationError(
                    f"Unable to authenticate {repr(response)}", response=response
                )
        else:
            _LOGGER.debug("Skipping mutual authentication, returning %r", response)

    def authenticate_user(self, request: Request, response: Response) -> None:
        """Handles user authentication with gssapi/kerberos.

        Manipulates request headers in place.
        """

        host = request.url.host
        auth_header = self.generate_request_header(response, host)
        _LOGGER.debug("Authorization header: %s", format_auth_header(auth_header))
        request.headers["Authorization"] = auth_header
        _LOGGER.debug("%r", response)

    def authenticate_server(self, response: Response) -> bool:
        """Uses GSSAPI to authenticate the server.

        Returns `True` on success, `False` on failure.
        """

        response_token = negotiate_value(response)
        _LOGGER.debug(
            "Authenticating server response: %s",
            base64.b64encode(response_token).decode() if response_token else "",
        )

        host = response.url.host

        try:
            self._context[host].step(in_token=response_token)
        except spnego.exceptions.SpnegoError:
            _LOGGER.exception("Context step failed")
            return False
        return True

    def generate_request_header(self, response: Response, host: str) -> str:
        """Generates the GSSAPI authentication token with kerberos.

        If any GSSAPI step fails, raise
        :class: `KerberosExchangeError <pi_web.exceptions.KerberosExchangeError`
        with failure detail.
        """

        # flags used by kerberos module
        gssflags = spnego.ContextReq.sequence_detect
        if self.delegate:
            gssflags |= spnego.ContextReq.delegate
        if self.mutual_authentication != MutualAuthentication.DISABLED:
            gssflags |= spnego.ContextReq.mutual_auth

        try:
            kerb_stage = "ctx init"
            # contexts still need to be stored by host, but hostname_override
            # allows use of an arbitrary hostname for the kerberos exchange
            # (eg, in cases of aliased hosts, internal vs external, CNAMEs
            # w/ name-based HTTP hosting)
            kerb_host = (
                self.hostname_override if self.hostname_override is not None else host
            )

            # split principal into user and password if defined
            username = self.principal
            password = None
            if isinstance(username, str):
                split = username.split(":", 1)
                if len(split) > 1:
                    username = split[0]
                    password = split[1]

            # to prevent failing compare headers test, don't pass password if None
            if password:
                self._context[host] = ctx = spnego.client(
                    username=username,
                    password=password,
                    hostname=kerb_host,
                    service=self.service,
                    channel_bindings=self._cbts.get(host, None),
                    context_req=gssflags,
                    protocol="kerberos",
                )
            else:
                self._context[host] = ctx = spnego.client(
                    username=username,
                    hostname=kerb_host,
                    service=self.service,
                    channel_bindings=self._cbts.get(host, None),
                    context_req=gssflags,
                    protocol="kerberos",
                )

            # use previous response from the server to continue the auth process
            negotiate_resp_value = negotiate_value(response)

            kerb_stage = "ctx step"
            gss_response = ctx.step(in_token=negotiate_resp_value)

            if gss_response is None:
                warnings.warn(
                    (
                        "Failed to perform negotiation step for security context. "
                        "The step returned a NoneType value."
                    ),
                    NegotiationStepFailedWarning,
                )
                return "Negotiate "

            return f"Negotiate {base64.b64encode(gss_response).decode()}"

        except spnego.exceptions.SpnegoError as e:
            _LOGGER.exception("%s failed", kerb_stage)
            raise KerberosExchangeError(
                f"{kerb_stage} failed: {str(e)}", response=response
            ) from e
