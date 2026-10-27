"""Optional public pyOpenSSL MemoryBIO adapter. No socket, private ABI or key log."""

import ssl
from cryptography.hazmat.primitives.serialization import Encoding


def hybrid_engine(sni, version):
    from inventory.host import Refused

    try:
        import OpenSSL
        from OpenSSL import SSL
        import cryptography
    except ImportError:
        raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM") from None
    if version != "TLSv1.3":
        raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
    provider = SSL.SSLeay_version(SSL.SSLEAY_VERSION).decode("ascii")
    import re

    match = re.match(r"^OpenSSL ([0-9]+)\.([0-9]+)\.", provider)
    sdk = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", OpenSSL.__version__)
    if not match or tuple(map(int, match.groups())) < (3, 5) or not sdk or tuple(map(int, sdk.groups())) < (26, 4, 0):
        raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_min_proto_version(SSL.TLS1_3_VERSION)
        context.set_max_proto_version(SSL.TLS1_3_VERSION)
        context.set_verify(SSL.VERIFY_NONE, lambda *args: True)  # Exact peer DER pin is checked by collector.
        context.set_options(SSL.OP_NO_TICKET)
        connection = SSL.Connection(context, None)
        connection.set_connect_state()
        connection.set_tlsext_host_name(sni.encode("ascii"))
    except SSL.Error:
        raise ssl.SSLError("TLS_PROVIDER_SETUP_FAILED") from None

    class Incoming:
        def write(self, data):
            try:
                if connection.bio_write(data) != len(data):
                    raise ssl.SSLError("TLS_PROVIDER_PARTIAL_BIO")
            except SSL.Error:
                raise ssl.SSLError("TLS_PROVIDER_INPUT_FAILED") from None

    class Outgoing:
        def __init__(self):
            self.buffer = bytearray()

        @property
        def pending(self):
            if not self.buffer:
                try:
                    self.buffer.extend(connection.bio_read(16384))
                except SSL.WantReadError:
                    pass
                except SSL.Error:
                    raise ssl.SSLError("TLS_PROVIDER_OUTPUT_FAILED") from None
            return len(self.buffer)

        def read(self, n):
            data = bytes(self.buffer[:n])
            del self.buffer[:n]
            return data

    class Engine:
        provider_metadata = {
            "openssl_version": provider,
            "pyopenssl_version": OpenSSL.__version__,
            "cryptography_version": cryptography.__version__,
        }

        def do_handshake(self):
            try:
                connection.do_handshake()
            except SSL.WantReadError:
                raise ssl.SSLWantReadError() from None
            except SSL.WantWriteError:
                raise ssl.SSLWantWriteError() from None
            except SSL.Error:
                raise ssl.SSLError("TLS_PROVIDER_HANDSHAKE_FAILED") from None

        def getpeercert(self, *, binary_form):
            if not binary_form:
                raise ValueError("Public DER only")
            try:
                cert = connection.get_peer_certificate(as_cryptography=True)
                return cert.public_bytes(Encoding.DER) if cert is not None else None
            except SSL.Error:
                raise ssl.SSLError("TLS_PROVIDER_CERTIFICATE_FAILED") from None

        def cipher(self):
            return (connection.get_cipher_name(), connection.get_protocol_version_name(), connection.get_cipher_bits())

        def version(self):
            return connection.get_protocol_version_name()

    return Engine(), Incoming(), Outgoing()
