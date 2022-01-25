Webauthn Erlang
=====

An simple server side implementation for supporting webauthn in erlang.

More information about Webauthn here:
* [w3c](https://w3c.github.io/webauthn/) - Official docs.
* [webauthn.guide](https://webauthn.guide/) - Good guide to get going.

The lib supports 3 functions:

### challenge()
Generates a challenge (32 random bytes in URL safe Base64 encoding)

### register_response()
Validates registration response and returns the public key and key handle.

### sign_response()
Validates response and returns the new counter value if the signature is valid.

**Note:** Only has support for `ecdsa` with `sha256` and curve `secp256r1`. Wich can be obtained by calling create (in the frontend) with:

```
pubKeyCredParams: [{alg: -7, type: "public-key"}],
```


