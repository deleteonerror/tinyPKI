# How to use the Tiny PKI

- [Default](#defaults)
  - [CA Private Keys](#ca-private-keys)
  - [Directories](#directories-default)
  - [Validity Periods](#validity-periods)
- [Submitting a Certificate Request](#submitting-a-certificate-request)
- [Submitting a CA Certificate Request](#submitting-a-ca-certificate-request)

## Defaults

### CA Private Keys

All keys are generated using *ECDSA 384* and are stored encrypted with *chacha20poly1305*

### Directories (default)

| Directory | Used for |
| --- | --- |
| `/var/tinyPKI/reqests` | The folder for incoming certificate request |
| `/var/tinyPKI/reqests/ca` | The folder for incoming Subordinary or Intermediate certificate requests to the *tiny_pki_root* |
| `/var/tinyPKI/certificates` | The folder for ISSUED certificates by the *tiny_pki_sub* |
| `/var/tinyPKI/certificates/ca` | The folder for ISSUED ca certificates by the *tiny_pki_root* |
| `/var/tinyPKI/revoke` | The folder for certificates which should be revoked by the *tiny_pki_sub* |
| `/var/tinyPKI/publish` | The folder where all ca's publish their certificates and revocation lists |

### Validity Periods

| type | Cert | CRL |
|:---| --- | --- |
| Root | 12 years | 120 days |
| Sub | 6 years | 90 days |
| EE | 1 year | :x: |


## Submitting a Certificate Request

Submitting a certificate request is a straightforward process:

1. Place your request in the `/var/tinyPKI/requests` directory.
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
