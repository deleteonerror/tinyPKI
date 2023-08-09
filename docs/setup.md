# How to Setup the Tiny PKI

a short ToDo list:

- [ ] [Prepare the environment](#host-preparation)
- [ ] [Initialize the Subordinary Certificate Authority](#initialize-the-subordinary-certificate-authority) \*
- [ ] [Initialize the Root Certificate Authority](#initialize-the-root-certificate-authority)
- [ ] [Finalize](#finalize)

*\*yes we do the sub before the root. this saves some repetitive steps.*

In this tutorial, we will begin by initializing the Subordinate Certificate Authority (Sub CA) using the command `tpiksub` within the *tiny_pki_sub* container. During this process, the Sub CA's private key is automatically generated and encrypted with the given passphrase. Following this, the Sub CA will automatically generate a Certificate Signing Request (CSR) for its certificate.

Next, we will turn our attention to the Root Certificate Authority (Root CA), initializing it by executing `tpikroot` inside the *tiny_pki_root* container. Similarly to the Sub CA, a private key will be created and encrypted with your passphrase during this phase. The Root CA then proceeds to create a self-signed certificate and a revocation list, which will be located at `/var/tinyPKI/publish/` if the default locations are adhered to.

After these steps, the Root CA will automatically issue the certificate for the Sub CA. Finally, we will run the `tpkisub` command once again to import the certificate.

How to issue request will be described in the usage documentation [here](./usage.md)

## Host preparation

1. Create a folder where your compose file and the config lives

    ``` shell
    mkdir -p ~/tinyPKI/config
    ```

2. download or create the config files

    The raw files are located [root](https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/configs/tinypki.root.example.json) [sub](https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/configs/tinypki.sub.example.json)  
    or just use `wget` >>

    ``` shell
        wget -O ./tinyPKI/config/root.json https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/configs/tinypki.root.example.json
        wget -O ./tinyPKI/config/sub.json https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/configs/tinypki.sub.example.json
    ```

    the content should look like this:

    ``` json
    {
    "common_name": "THE NAME OF YOUR CA",
    "country_iso": "US",
    "organization": "A FUNNY ORGANIZATION NAME",
    "organizational_unit": "A FUNNY ORGANIZATIONAL UNIT",
    "base_url": "http://pki.example.com"
    }    
    ```

    *Important*: The `basu_url` shoul be a url where you plan to publish the revocation lists and ca certificates for 'public' access. All applications which use a proper certificate validation will check this url for revocation lists.

3. download or create the **compose** file

    The raw file is located [here](https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/deploy/compose.yml)  
    or just use `wget` >>

    ```shell
    wget -O ./tinyPKI/compose.yml https://raw.githubusercontent.com/deleteonerror/tinyPKI/main/deploy/compose.yml
    ```

    the content should look like this:

    ``` yml
    services:
    tinyroot:
        image: deleteonerror/tinypki_root:latest
        container_name: tiny-pki-root
        network_mode: "none"
        volumes:
        - root-store:/var/lib/tinyPKI:rw
        # Important: do not use a named volume and use the same directory as on the Sub CA
        - /var/tinyPKI:/var/tinyPKI:rw
        # environment:
        # - TINY_LOG=DEBUG
        configs:
        - source: root-config
            target: /var/tinyPKI/root.config.json

    tinysub:
        image: deleteonerror/tinypki_sub:latest
        container_name: tiny-pki-sub
        network_mode: "none"
        volumes:
        - sub-store:/var/lib/tinyPKI:rw
        # Important: do not use a named volume and use the same directory as on the Root CA
        - /var/tinyPKI:/var/tinyPKI:rw
        # environment:
        # - TINY_LOG=DEBUG
        configs:
        - source: sub-config
            target: /var/tinyPKI/sub.config.json

    volumes:
    pki-work:
    root-store:
    sub-store:

    configs:
    root-config:
        file: ./config/root.json
    sub-config:
        file: ./config/sub.json
    ```

4. set permission on the *work* location

    This volume is a shared store for the root and the sub, so we have to ensure that both can write to it

    ``` shell
    sudo chown root:5000 /var/tinyPKI
    ```

    5000 is the group of both users inside the containers

5. deploy the Container

    ``` shell
    docker compose -f compose.yml -p tiny_pki up -d
    ```

## Initialize the Subordinary Certificate Authority

list your running docker containers with:

``` shell
docker ps
```

run:

``` shell
docker exec -it <id of your tiny_pki_SUB container> sh tpkisub
```

\* *you don't need to type the full id, the start of the container id is enough as long at it is unique.*
  
this will open a shell inside the container. Make sure you chose a save and secure passphrase.

## Initialize the Root Certificate Authority

again list your running docker containers with:

``` shell
docker ps
```

run:

``` shell
docker exec -it <id of your tiny_pki_ROOT container> sh tpkiroot
```

\* *you don't need to type the full id, the start of the container id is enough as long at it is unique.*
  
this will open a shell inside the container. Make sure you chose a save and secure passphrase.

## Finalize

All what's left is copy the content of the publish folder `/var/tinyPKI/publish` (\*.crl,\*.cer) to the web server, serving your *base_url* and start issuing certificates.
