from __future__ import annotations

from typing import TYPE_CHECKING

from httpx import HTTPError, RequestError

if TYPE_CHECKING:
    from httpx import Response


class NegotiationStepFailedWarning(Warning):
    pass


class NoCertificateRetrievedWarning(Warning):
    pass


class UnknownSignatureAlgorithmOID(Warning):
    pass


class MutualAuthenticationError(RequestError):
    """Unable to verify server."""

    def __init__(self, message: str, *, response: "Response") -> None:
        super().__init__(message, request=response.request)
        self.response = response


class KerberosExchangeError(RequestError):
    """Kerberos exchange failed."""

    def __init__(self, message: str, *, response: "Response") -> None:
        super().__init__(message, request=response.request)
        self.response = response


class KerberosUnsupported(Exception):
    """An internal error raised if the server does not respond with the
    'WWW-Authenticate: Negotiate' header.
    """
