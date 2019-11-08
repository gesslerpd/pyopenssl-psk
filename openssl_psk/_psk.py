from OpenSSL.SSL import Context, Connection, _ffi, _lib
from OpenSSL.SSL import _CallbackExceptionHelper, _text_to_bytes_and_warn, wraps, _openssl_assert


class _PskServerHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as a PSK server callback.
    """

    def __init__(self, callback):
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, identity, psk, max_psk_len):
            try:
                conn = Connection._reverse_mapping[ssl]

                client_identity = _ffi.string(identity)

                # Call the callback
                # returning an empty string signifies a failed handshake
                psk_str = callback(conn, client_identity)

                psk_str = _text_to_bytes_and_warn(
                    "psk",
                    psk_str
                )

                if not isinstance(psk_str, bytes):
                    raise TypeError("Client PSK "
                                    "must be a bytestring.")

                psk_str_len = len(psk_str)

                assert psk_str_len <= max_psk_len

                _ffi.memmove(psk, psk_str, psk_str_len)

                return psk_str_len
            except Exception as e:
                self._problems.append(e)
                return 0

        self.callback = _ffi.callback(
            "unsigned int(*)(SSL *, const char *, unsigned char *, unsigned int)",
            wrapper
        )


class _PskClientHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as a PSK client callback.
    """

    def __init__(self, callback):
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, hint, identity, max_identity_len, psk, max_psk_len):
            try:
                conn = Connection._reverse_mapping[ssl]

                if hint == _ffi.NULL:
                    # identity hint empty if NULL pointer
                    identity_hint = b''
                else:
                    identity_hint = _ffi.string(hint)

                psk_identity, psk_str = callback(conn, identity_hint)

                psk_identity = _text_to_bytes_and_warn(
                    "psk_identity",
                    psk_identity
                )

                if not isinstance(psk_identity, bytes):
                    raise TypeError("Client PSK identity "
                                    "must be a bytestring.")

                psk_identity_len = len(psk_identity)
                assert psk_identity_len <= max_identity_len

                psk_str = _text_to_bytes_and_warn(
                    "psk",
                    psk_str
                )

                if not isinstance(psk_str, bytes):
                    raise TypeError("Client PSK "
                                    "must be a bytestring.")

                psk_str_len = len(psk_str)
                assert psk_str_len <= max_psk_len

                _ffi.memmove(identity, psk_identity, psk_identity_len)
                _ffi.memmove(psk, psk_str, psk_str_len)

                return psk_str_len
            except Exception as e:
                self._problems.append(e)
                return 0

        self.callback = _ffi.callback(
            "unsigned int (*)(SSL *, const char *, char *, unsigned int, unsigned char *, unsigned int)",
            wrapper
        )


def use_psk_identity_hint(self, hint):
    """
    Set the server PSK identity hint.

    :param bytes hint: server PSK identity hint

    """
    hint = _text_to_bytes_and_warn("hint", hint)

    if not isinstance(hint, bytes):
        raise TypeError("hint must be a byte string.")

    _openssl_assert(
        _lib.SSL_CTX_use_psk_identity_hint(self._context, hint) == 1
    )


def set_psk_server_callback(self, callback):
    """
    Set a callback to populate the server PSK.

    :param callable callback:
        The callback function. It will be invoked with two
        arguments: the Connection, and a byte string containing the PSK
        identity from the client. The callback must return a byte string
        containing the server PSK that corresponds to the client PSK
        identity. If the callback raises an exception, a handshake error occurs.

    """
    if not callable(callback):
        raise TypeError("callback must be callable")

    self._psk_server_helper = _PskServerHelper(callback)
    self._psk_server_callback = self._psk_server_helper.callback
    _lib.SSL_CTX_set_psk_server_callback(
        self._context,
        self._psk_server_callback
    )


def set_psk_client_callback(self, callback):
    """
    Set a callback to populate the client PSK identity and PSK.

    :param callback:
        The callback function. It will be invoked with two
        arguments: the Connection, and a byte string containing the PSK
        identity hint from the server. The callback must return a two
        element tuple: a byte string containing the client PSK identity,
        and a byte string containing the client PSK. These byte strings
        will be sent to the server during a handshake.

    """
    if not callable(callback):
        raise TypeError("callback must be callable")

    self._psk_client_helper = _PskClientHelper(callback)
    self._psk_client_callback = self._psk_client_helper.callback
    _lib.SSL_CTX_set_psk_client_callback(
        self._context,
        self._psk_client_callback
    )


def patch_context():
    """
    Add PSK related methods to the `OpenSSL.SSL.Context` class.
    """
    try:
        Context.use_psk_identity_hint
    except AttributeError:
        Context.use_psk_identity_hint = use_psk_identity_hint
        Context.set_psk_server_callback = set_psk_server_callback
        Context.set_psk_client_callback = set_psk_client_callback
