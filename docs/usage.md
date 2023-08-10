# How to use the Tiny PKI

- [Default](#defaults)
  - [CA Private Keys](#ca-private-keys)
  - [Directories](#directories-default)
  - [Validity Periods](#validity-periods)
- [Submitting a Certificate Request](#submitting-a-certificate-request)
- [Submitting a CA Certificate Request](#submitting-a-ca-certificate-request)
- [Revoke a Certificate](#revoke-a-certificate)

## Defaults

### CA Private Keys

All keys are generated using *ECDSA 384* and are stored encrypted with *chacha20poly1305*

### Directories (default)

| Directory | Used for |
| --- | --- |
| `/var/tinyPKI/reqests` | The folder for incoming certificate request |
| `/var/tinyPKI/reqests/webserver` | The folder for incoming `WebServer` certificate request |
| `/var/tinyPKI/reqests/client` | The folder for incoming `Client` certificate request |
| `/var/tinyPKI/reqests/code` | The folder for incoming `CodeSigning` certificate request |
| `/var/tinyPKI/reqests/server` | The folder for incoming `Server` certificate request |
| `/var/tinyPKI/reqests/ocsp` | The folder for incoming `OCSP` certificate request |
| `/var/tinyPKI/reqests/ca` | The folder for incoming Subordinary or Intermediate certificate requests to the *tiny_pki_root* |
| `/var/tinyPKI/certificates` | The folder for ISSUED certificates by the *tiny_pki_sub* |
| `/var/tinyPKI/certificates/ca` | The folder for ISSUED ca certificates by the *tiny_pki_root* |
| `/var/tinyPKI/revoke` | The folder for certificates which should be revoked by the *tiny_pki_sub* |

### Validity Periods

| type | Cert | CRL |
|:---| --- | --- |
| Root | 12 years | 120 days |
| Sub | 6 years | 90 days |
| EE | 1 year | :x: |

## Submitting a Certificate Request

Submitting a certificate request is a straightforward process:

1. Place your request in the directory `/var/tinyPKI/requests` or in any subdirectory of this path, depending on your certificate needs. Refer to the directory table to select the correct directory.
2. Retrieve the container ID of your *tiny_pki_sub* instance.
3. Execute the following command: `docker exec -it <id of your tiny_pki_SUB container> sh -c tpkisub`.
4. Enter your passphrase when prompted. If there are any errors, they will be displayed in the command line.
5. If no errors occur, your certificate will be issued, and you can find it at `/var/tinyPKI/certificates`.

## Submitting a CA Certificate Request

Submitting a Sub CA certificate request is a straightforward process:

1. Place your request in the `/var/tinyPKI/requests/ca` directory.
2. Retrieve the container ID of your *tiny_pki_root* instance.
3. Execute the following command: `docker exec -it <id of your tiny_pki_ROOT container> sh -c tpkiroot`.
4. Enter your passphrase of the Root CA when prompted. If there are any errors, they will be displayed in the command line.
5. If no errors occur, your certificate will be issued, and you can find it at `/var/tinyPKI/certificates/ca`.

## Revoke a Certificate

Revoking a certificate:

1. Place the certificate you want to remove in the `/var/tinyPKI/revoke` directory.
2. Retrieve the container ID of your *tiny_pki_sub* instance.
3. Execute the following command: `docker exec -it <id of your tiny_pki_sub container> sh -c tpkisub`.
4. Enter your passphrase of the CA when prompted. If there are any errors, they will be displayed in the command line.
5. If no errors occur, your certificate will be revoked, and you can find a new CRL at `/var/tinyPKI/publish`.
6. Copy the \*.crl to your web server.
