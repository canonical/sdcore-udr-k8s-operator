resource "juju_application" "udr" {
  name  = "udr"
  model = var.model_name

  charm {
    name    = "sdcore-udr-k8s"
    channel = var.channel
  }

  units = 1
  trust = true
}

resource "juju_integration" "udr-db" {
  model = var.model_name

  application {
    name     = juju_application.udr.name
    endpoint = "database"
  }

  application {
    name     = var.db_application_name
    endpoint = "database"
  }
}

resource "juju_integration" "udr-certs" {
  model = var.model_name

  application {
    name     = juju_application.udr.name
    endpoint = "certificates"
  }

  application {
    name     = var.certs_application_name
    endpoint = "certificates"
  }
}

resource "juju_integration" "udr-nrf" {
  model = var.model_name

  application {
    name     = juju_application.udr.name
    endpoint = "fiveg_nrf"
  }

  application {
    name     = var.nrf_application_name
    endpoint = "fiveg-nrf"
  }
}

