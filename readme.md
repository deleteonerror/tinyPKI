# tiny PKI

A tiny PKI for Home, Lab and Dev usage.

- setup documentation [here](./docs/setup.md)
- usage documentation [here](./docs/usage.md)

## Validity periods

| type | Cert | CRL |
|:---| --- | --- |
| Root | 12 years | 120 days |
| Sub | 6 years | 90 days |
| EE | 1 year | :x: |

## security considerations

The private key of the Certificate Authority

- is chacha20 encrypted
- is stored on the filesystem

The configuration

- is signed by the ca, manual changes to the config files will result in a broken ca

## External Dependencies you have to TRUST

only `golang.org/x` modules are used

## maybe feature

- file system watcher for the sub ca `fsnotify`
- passphrase file
- docker image
  - docker secret files support
- revocation reasons
- publish to LDAP
- Yubikey as Hardware Key Storage

## never a feature

- HSM integration
- CA renewal with new name
- CA renewal with same key
- Root private key export
- RSA support
