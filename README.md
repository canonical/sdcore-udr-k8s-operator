# Aether SD-Core UDR Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-udr-k8s/badge.svg)](https://charmhub.io/sdcore-udr-k8s)

A Charmed Operator for Aether SD-Core's Unified Data Repository (UDR) component for K8s. 

## Usage

```bash
juju deploy mongodb-k8s --trust --channel=6/beta
juju deploy sdcore-nrf-k8s --channel=1.5/edge
juju deploy sdcore-udr-k8s --channel=1.5/edge
juju deploy self-signed-certificates
juju deploy sdcore-nms-k8s --channel=1.5/edge

juju integrate mongodb-k8s sdcore-nrf-k8s
juju integrate mongodb-k8s sdcore-udr-k8s:common_database
juju integrate mongodb-k8s sdcore-udr-k8s:auth_database
juju integrate sdcore-nms-k8s:common_database mongodb-k8s:database
juju integrate sdcore-nms-k8s:auth_database mongodb-k8s:database
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s:fiveg_nrf sdcore-udr-k8s:fiveg_nrf
juju integrate sdcore-udr-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-udr-k8s:sdcore-config sdcore-nms-k8s:sdcore-config
```

## Image

- **udr**: `ghcr.io/canonical/sdcore-udr:1.4.1`

