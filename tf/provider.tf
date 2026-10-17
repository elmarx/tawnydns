provider "powerdns" {
  # create a token with
  # `cargo run -- token create example.com`
  # might require `cargo run -- key gen` prior
  api_key = var.tenant_api_key
}

variable "tenant_api_key" {
  description = "Tenant-specific API key"
}
