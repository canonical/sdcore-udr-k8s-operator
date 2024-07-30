# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.sdcore-udr-k8s.name
}

output "common_database_endpoint" {
  description = "Name of the endpoint to integrate with MongoDB for common_database using mongodb_client interface."
  value       = "common_database"
}

output "auth_database_endpoint" {
  description = "Name of the endpoint to integrate with MongoDB for auth_database using mongodb_client interface."
  value       = "auth_database"
}

output "fiveg_nrf_endpoint" {
  description = "Name of the endpoint to to integrate with NRF using fiveg_nrf interface."
  value       = "fiveg_nrf"
}

output "certificates_endpoint" {
  description = "Name of the endpoint to get the X.509 certificate using tls-certificates interface."
  value       = "certificates"
}

output "logging_endpoint" {
  description = "Name of the endpoint used to integrate with the Logging provider."
  value       = "logging"
}

output "sdcore_config_endpoint" {
  description = "Name of the endpoint used to integrate with the NMS."
  value       = "sdcore-config"
}

# Provided integration endpoints

output "metrics_endpoint" {
  description = "Exposes the Prometheus metrics endpoint providing telemetry about the UDR instance."
  value       = "metrics-endpoint"
}