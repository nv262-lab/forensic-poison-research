module "aws" { source = "./modules/aws" prefix = var.prefix region = var.aws_region }
module "azure" { source = "./modules/azure" prefix = var.prefix }
module "gcp" { source = "./modules/gcp" prefix = var.prefix project = var.gcp_project region = var.gcp_region }
