terraform {
  required_version = ">= 1.11"

  required_providers {
    # 2.1.1 is the floor: the first release with the empty-array-as-map fix
    # (upstream rixlhq/terraform-provider-netcup PR #47).
    netcup = {
      source  = "rixlhq/netcup"
      version = ">= 2.1.1, < 3.0.0"
    }
  }
}
