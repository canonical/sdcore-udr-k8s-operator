# SD-Core UDR Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-udr/badge.svg)](https://charmhub.io/sdcore-udr)

A Charmed Operator for SD-Core's Unified Data Repository (UDR) component. 

## Usage

```bash
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy sdcore-nrf --trust --channel=edge
juju deploy sdcore-udr --trust --channel=edge
juju deploy self-signed-certificates --channel=beta
juju integrate mongodb-k8s sdcore-nrf
juju integrate mongodb-k8s sdcore-udr:database
juju integrate sdcore-nrf:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf sdcore-udr:fiveg_nrf
juju integrate sdcore-udr:certificates self-signed-certificates:certificates
```

## Image

- **udr**: `ghcr.io/canonical/sdcore-udr:1.3`
