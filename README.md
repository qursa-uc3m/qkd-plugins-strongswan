# QKD plugins for strongSwan

This repository contains plugins for strongSwan that implement quantum key distribution (QKD) protocols for the IKEv2 protocol.

## Building and Installing

**Note:** Tested in Ubuntu 22.04 and Ubuntu 24.04.

### QKD Configuration Options

The plugins support different configuration options:

**QKD Initiation Mode:**

- `--with-qkd-initiation-mode=client` (default): Client initiates QKD key exchange
- `--with-qkd-initiation-mode=server`: Server initiates QKD key exchange

**ETSI API Version:**

- `--with-etsi-api-version=014` (default): Use ETSI GS QKD 014 API
- `--with-etsi-api-version=004`: Use ETSI GS QKD 004 API


### Building the Plugins

First build strongSwan with the following options:

```bash
./scripts/build_strongswan.sh
```

Initialize the build system:

```bash
autoreconf -i
```

Configure the build system:

```bash
./configure --with-strongswan-headers=/usr/include/strongswan \
            --with-plugin-dir=/usr/lib/ipsec/plugins \
            --with-qkd-etsi-api=/usr/local \
            --with-qkd-kem-provider=/usr/local \
            --with-qkd-initiation-mode=client \
            --with-etsi-api-version=014
```

Build and install the plugins:

```bash
make
sudo make install
```

## Using the Plugins

The plugins provide the following key exchange methods:

### QKD Plugin

`qkd`: Pure QKD key exchange

### QKD-KEM Plugin

* `qkd_kyber1`, `qkd_kyber3`, `qkd_kyber5`: QKD with Kyber
* `qkd_mlkem1`, `qkd_mlkem3`, `qkd_mlkem5`: QKD with ML-KEM
* `qkd_frodoa1`, `qkd_frodos1`, `qkd_frodoa3`, `qkd_frodos3`, `qkd_frodoa5`, `qkd_frodos5`: QKD with FrodoKEM
* `qkd_bike1`, `qkd_bike3`, `qkd_bike5`: QKD with BIKE
* `qkd_hqc1`, `qkd_hqc3`, `qkd_hqc5`: QKD with HQC

### Example Configurations

Use these methods in your connection configurations. For example:

For Client (Alice) add to `swanctl.conf`:

```config
connections {
   home {
      # ...
      proposals = aes128-sha256-qkd
      children {
         net {
            esp_proposals = aes128-sha256-qkd
         }
      }
   }
}
```

And for the Server (Bob) add to `swanctl.conf`:

```config
connections {
   rw {
      # ...
      proposals = aes128-sha256-qkd
      children {
         net {
            esp_proposals = aes128-sha256-qkd
         }
      }
   }
}
```

Make sure to load the plugins in your `strongswan.conf`, for example:

```config
charon {
    ...
    load = random nonce openssl hmac pem pubkey x509 kernel-netlink socket-default vici qkd qkd-kem
}
pki {
   load = plugins: random drbg x509 pubkey pkcs1 pkcs8 pkcs12 pem openssl qkd qkd-kem
}
```

You can see a working dockerized example in [qursa-uc3m/qkd-ipsec-docker-test](https://github.com/qursa-uc3m/qkd-ipsec-docker-test).

## Contributing

Contributions are welcome!