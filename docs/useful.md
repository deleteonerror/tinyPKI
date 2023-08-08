# a collection of useful commands

## Validate Certificates (openssl)

``` shell
openssl x509 -noout -text -in test.cer
```

## Docker build x

enable plugin:

``` shell
docker buildx create --use
```
