# tiny PKI

A tiny PKI for Home, Lab and Dev usage.

- setup documentation [here](./docs/setup.md)
- usage documentation [here](./docs/usage.md)

## security considerations

The private key of the Certificate Authority

- is chacha20poly1305 encrypted
- is stored on the filesystem with 0600 permissions

The configuration

- is signed by the ca, manual changes to the config files will result in a broken ca

## External Dependencies you have to TRUST

only `golang.org/x` modules are used

## maybe feature

- decoding ASN.1 of csr's
- file system watcher for the sub ca `fsnotify`
- passphrase file
- docker image
  - docker secret files support
- revocation reasons
- publish to LDAP
- Yubikey as Hardware Key Storage

## Out of scope for this project

- HSM integration
- CA renewal with new name
- CA renewal with same key
- Root private key export
- Server Generated keys other than CA keys
- Key recovery
- RSA support
