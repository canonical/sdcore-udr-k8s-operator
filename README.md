<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-udr"><img src="https://charmhub.io/sdcore-udr/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-udr-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-udr-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core UDR Operator</h1>
</div>

A Charmed Operator for SD-Core's Unified Data Repository (UDR) component. 

## Usage

```bash
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy sdcore-nrf --trust --channel=edge
juju deploy sdcore-udr --trust --channel=edge
juju integrate mongodb-k8s sdcore-nrf
juju integrate mongodb-k8s sdcore-udr:database
juju integrate sdcore-nrf sdcore-udr:fiveg_nrf
```

## Image

- **udr**: `ghcr.io/canonical/sdcore-udr:1.3`
