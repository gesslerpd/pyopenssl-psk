# pyopenssl-psk

Add PSK support to pyOpenSSL.

## Installation

```
$ pip install pyopenssl-psk
```

## API

### Patch Method

- `patch_context()`

  Add PSK related methods to the `OpenSSL.SSL.Context` class.

```python
from openssl_psk import patch_context

patch_context()
```

### Server Methods

- `Context.use_psk_identity_hint(hint: bytes) -> None`

  Set the server PSK identity hint.

- `Context.set_psk_server_callback(callback: server_callback) -> None`
  
  Set a callback to populate the server PSK.

  `server_callback(connection: Connection, client_identity: bytes) -> psk: bytes`

  User provided callback function to populate the connection PSK.

```python
from OpenSSL.SSL import Context, Connection, TLSv1_2_METHOD

PSK_MAP = {
    b'pre_shared_key_identity': b'pre_shared_key',
}

def server_callback(conn, client_identity):
    return PSK_MAP[client_identity]

ctx = Context(TLSv1_2_METHOD)
ctx.set_cipher_list(b'PSK')
ctx.use_psk_identity_hint(b'pre_shared_key_identity_hint')
ctx.set_psk_server_callback(server_callback)
server = Connection(ctx)
```

### Client Methods

- `Context.set_psk_client_callback(callback: client_callback) -> None`

  Set a callback to populate the client PSK identity and PSK.
  
  `client_callback(connection: Connection, identity_hint: bytes) -> tuple(psk_identity: bytes, psk: bytes)`

  User provided callback function to populate the connection PSK identity and PSK.

```python
from OpenSSL.SSL import Context, Connection, TLSv1_2_METHOD

def client_callback(conn, identity_hint):
    return (b'pre_shared_key_identity', b'pre_shared_key')

ctx = Context(TLSv1_2_METHOD)
ctx.set_cipher_list(b'PSK')
ctx.set_psk_client_callback(client_callback)
client = Connection(ctx)
```

See `OpenSSL.SSL` [documentation](https://www.pyopenssl.org/en/stable/api/ssl.html) for more information.
