# tiny PKI

A tiny PKI for Home, Lab and Dev usage.

## Validity periods

- Root Certificates default to 12 year
- CRL's of Root CA's default to 120 days

- Sub CA Certificates default to 6 year
- CRL's of Root CA's default to 30 days

- End entity Certificates default to 1 year

## security considerations

The private key of the Certificate Authority
- is chacha20 encrypted
- is stored on the filesystem
The configuration
- is signed by the ca, manual changes to the config files will result in a broken ca

## External Dependencies you have to TRUST

only `golang.org/x` modules are used

## maybe feature

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
