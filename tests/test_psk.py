
import pytest

from OpenSSL.SSL import TLSv1_2_METHOD

from OpenSSL.SSL import Error, WantReadError
from OpenSSL.SSL import Context, Connection

from openssl_psk import patch_context

patch_context()


def interact_in_memory(client_conn, server_conn):
    """
    Try to read application bytes from each of the two `Connection` objects.
    Copy bytes back and forth between their send/receive buffers for as long
    as there is anything to copy.  When there is nothing more to copy,
    return `None`.  If one of them actually manages to deliver some application
    bytes, return a two-tuple of the connection from which the bytes were read
    and the bytes themselves.
    """
    wrote = True
    while wrote:
        # Loop until neither side has anything to say
        wrote = False

        # Copy stuff from each side's send buffer to the other side's
        # receive buffer.
        for (read, write) in [(client_conn, server_conn),
                              (server_conn, client_conn)]:

            # Give the side a chance to generate some more bytes, or succeed.
            try:
                data = read.recv(2 ** 16)
            except WantReadError:
                # It didn't succeed, so we'll hope it generated some output.
                pass
            else:
                # It did succeed, so we'll stop now and let the caller deal
                # with it.
                return (read, data)

            while True:
                # Keep copying as long as there's more stuff there.
                try:
                    dirty = read.bio_read(4096)
                except WantReadError:
                    # Okay, nothing more waiting to be sent.  Stop
                    # processing this send buffer.
                    break
                else:
                    # Keep track of the fact that someone generated some
                    # output.
                    wrote = True
                    write.bio_write(dirty)


def handshake_in_memory(client_conn, server_conn):
    """
    Perform the TLS handshake between two `Connection` instances connected to
    each other via memory BIOs.
    """
    client_conn.set_connect_state()
    server_conn.set_accept_state()

    for conn in [client_conn, server_conn]:
        try:
            conn.do_handshake()
        except WantReadError:
            pass

    interact_in_memory(client_conn, server_conn)


class TestPSK(object):
    """
    Tests for PyOpenSSL's PSK support.
    """

    def _client_connection(self, callback):
        """
        Builds a client connection suitable for using PSK.
        :param callback: The callback to register for PSK.
        """
        ctx = Context(TLSv1_2_METHOD)
        ctx.set_psk_client_callback(callback)
        ctx.set_cipher_list(b'PSK')
        client = Connection(ctx)
        client.set_connect_state()
        return client

    def _server_connection(self, callback, hint=b'identity_hint'):
        """
        Builds a server connection suitable for using PSK.
        :param callback: The callback to register for PSK.
        :param hint: The server PSK identity hint.
        """
        ctx = Context(TLSv1_2_METHOD)
        ctx.use_psk_identity_hint(hint)
        ctx.set_psk_server_callback(callback)
        ctx.set_cipher_list(b'PSK')
        server = Connection(ctx)
        server.set_accept_state()
        return server

    def test_valid_handshake(self):
        """
        The client sends it's PSK and is verified by the server.
        """

        PSK_MAP = {
            b'pre_shared_key_identity': b'pre_shared_key',
            b'pre_shared_key_identity1': b'pre_shared_key1',
            b'pre_shared_key_identity2': b'pre_shared_key2',
            b'pre_shared_key_identity3': b'pre_shared_key3',
        }

        def server_callback(conn, client_identity):
            return PSK_MAP[client_identity]

        for identity, secret in PSK_MAP.items():

            def client_callback(conn, identity_hint):
                assert identity_hint == b'identity_hint'
                return (identity, secret)

            client = self._client_connection(callback=client_callback)
            server = self._server_connection(callback=server_callback)
            handshake_in_memory(client, server)

            def client_callback_bad_identity(conn, identity_hint):
                return (secret, secret)

            client = self._client_connection(
                callback=client_callback_bad_identity)
            server = self._server_connection(callback=server_callback)
            with pytest.raises(Error):
                handshake_in_memory(client, server)

            def client_callback_bad_psk(conn, identity_hint):
                return (identity, identity)

            client = self._client_connection(callback=client_callback_bad_psk)
            server = self._server_connection(callback=server_callback)
            with pytest.raises(Error):
                handshake_in_memory(client, server)

    def test_bad_callbacks(self):
        """
        If the callbacks are not callable,
        raise error.
        """
        with pytest.raises(TypeError):
            self._server_connection(callback=3)

        with pytest.raises(TypeError):
            self._client_connection(callback=3)

    def test_server_returns_empty_string_terminates_handshake(self):
        """
        If the server returns empty string from its callback,
        the handshake fails.
        """
        def server_callback(*args):
            return b''

        def client_callback(*args):
            return (b'identity', b'psk')

        client = self._client_connection(callback=client_callback)
        server = self._server_connection(callback=server_callback)

        with pytest.raises(Error):
            handshake_in_memory(client, server)

    def test_empty_string_server_identity_hint(self):
        """
        If the server can send an empty identity hint.
        """
        def server_callback(conn, client_identity):
            assert client_identity == b'client_identity'
            return b'pre_shared_key'

        def client_callback(conn, identity_hint):
            assert identity_hint == b''
            return (b'client_identity', b'pre_shared_key')

        client = self._client_connection(callback=client_callback)
        server = self._server_connection(callback=server_callback, hint=b'')

        handshake_in_memory(client, server)

        client = self._client_connection(callback=client_callback)
        server = self._server_connection(callback=server_callback, hint=b'')

        handshake_in_memory(client, server)

    def test_non_bytestring_server_identity_hint(self):
        """
        If the server identity hint is not convertable to bytestrings,
        raise error.
        """
        with pytest.raises(TypeError):
            self._server_connection(callback=None, hint=3)

    def test_psk_mismatch_terminates_handshake(self):
        """
        If the PSKs do not match,
        the handshake fails.
        """
        def server_callback(*args):
            return b'good_psk'

        def client_callback(*args):
            return (b'identity', b'bad_psk')

        client = self._client_connection(callback=client_callback)
        server = self._server_connection(callback=server_callback)

        with pytest.raises(Error):
            handshake_in_memory(client, server)

    def test_non_bytestring_terminates_handshakes(self):
        """
        If the PSK info is not convertable to bytestrings,
        the handshake fails.
        """
        def client_callback(*args):
            return (b'identity', b'psk')

        def bad_server_callback(*args):
            return 3

        def bad_identity_client_callback(*args):
            return (3, b'bad_psk')

        def bad_psk_client_callback(*args):
            return (b'identity', 3)

        client = self._client_connection(callback=client_callback)
        server = self._server_connection(callback=bad_server_callback)

        with pytest.raises(Error):
            handshake_in_memory(client, server)

        client = self._client_connection(callback=bad_identity_client_callback)
        server = self._server_connection(callback=bad_server_callback)

        with pytest.raises(Error):
            handshake_in_memory(client, server)

        client = self._client_connection(callback=bad_psk_client_callback)
        server = self._server_connection(callback=bad_server_callback)

        with pytest.raises(Error):
            handshake_in_memory(client, server)
