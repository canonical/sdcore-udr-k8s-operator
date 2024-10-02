# SD-Core UDR K8s Terraform Module

This folder contains a base [Terraform][Terraform] module for the sdcore-udr-k8s charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm deployment onto any Kubernetes environment managed by [Juju][Juju].

The base module is not intended to be deployed in separation (it is possible though), but should rather serve as a building block for higher level modules.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment options (Juju model name, channel or application name).
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations), but also by exposing the application name.
- **versions.tf** - Defines the Terraform provider.

## Using sdcore-udr-k8s base module in higher level modules

If you want to use `sdcore-udr-k8s` base module as part of your Terraform module, import it like shown below.

```text
data "juju_model" "my_model" {
  name = "my_model_name"
}

module "udr" {
  source                 = "git::https://github.com/canonical/sdcore-udr-k8s-operator//terraform"
  model = juju_model.my_model.name
  # Optional Configurations
  # channel                        = "put the Charm channel here" 
  # app_name                       = "put the application name here" 
}
```

Create the integrations, for instance:

```text
resource "juju_integration" "udr-nms" {
  model = var.model_name

  application {
    name     = module.udr.app_name
    endpoint = module.udr.requires.sdcore_config
  }

  application {
    name     = module.nms.app_name
    endpoint = module.nms.provides.sdcore_config
  }
}
```

The complete list of available integrations can be found [here][udr-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[udr-integrations]: https://charmhub.io/sdcore-udr-k8s/integrations
