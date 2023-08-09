# a collection of useful commands

## Validate Certificates (openssl)

``` shell
openssl x509 -noout -text -in test.cer
```

## Validate Certificate Request (openssl)

``` shell
openssl req -noout -text -in test.req  
```

## Docker build x

enable plugin:

``` shell
docker buildx create --use
```
