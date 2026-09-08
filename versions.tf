terraform {
  required_version = ">= 1.11"

  required_providers {
    netcup = {
      source  = "rixlhq/netcup"
      version = "~> 1.2"
    }
  }
}
