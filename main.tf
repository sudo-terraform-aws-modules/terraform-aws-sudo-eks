resource "aws_eks_cluster" "cluster" {
  count = local.create ? 1 : 0

  name                      = var.cluster_name
  role_arn                  = local.cluster_role
  version                   = var.cluster_version
  enabled_cluster_log_types = var.cluster_enabled_log_types

  access_config {
    authentication_mode = var.authentication_mode

    # See access entries below - this is a one time operation from the EKS API.
    # Instead, we are hardcoding this to false and if users wish to achieve this
    # same functionality, we will do that through an access entry which can be
    # enabled or disabled at any time of their choosing using the variable
    # var.enable_cluster_creator_admin_permissions
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    security_group_ids      = compact(distinct(concat(var.cluster_additional_security_group_ids, [local.cluster_security_group_id])))
    subnet_ids              = coalescelist(var.control_plane_subnet_ids, var.subnet_ids)
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
  }
  dynamic "kubernetes_network_config" {
    for_each = [1]

    content {
      ip_family         = var.cluster_ip_family
      service_ipv4_cidr = var.cluster_service_ipv4_cidr
    }
  }
  dynamic "encryption_config" {
    for_each = local.enable_cluster_encryption_config ? [var.cluster_encryption_config] : []

    content {
      provider {
        key_arn = var.create_kms_key ? module.kms.key_arn : encryption_config.value.provider_key_arn
      }
      resources = encryption_config.value.resources
    }
  }

  tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
    var.cluster_tags,
  )

  timeouts {
    create = try(var.cluster_timeouts.create, null)
    update = try(var.cluster_timeouts.update, null)
    delete = try(var.cluster_timeouts.delete, null)
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster,
    aws_security_group_rule.cluster,
    aws_security_group_rule.node,
    aws_cloudwatch_log_group.log_group,
  ]
}

resource "aws_ec2_tag" "cluster_primary_security_group" {
  # This should not affect the name of the cluster primary security group
  # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2006
  # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2008
  for_each = { for k, v in merge(var.tags, var.cluster_tags) :
    k => v if local.create && k != "Name" && var.create_cluster_primary_security_group_tags && v != null
  }

  resource_id = aws_eks_cluster.cluster[0].vpc_config[0].cluster_security_group_id
  key         = each.key
  value       = each.value
}

resource "aws_cloudwatch_log_group" "log_group" {
  count = local.create && var.create_cloudwatch_log_group ? 1 : 0

  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id
  log_group_class   = var.cloudwatch_log_group_class

  tags = merge(
    var.tags,
    var.cloudwatch_log_group_tags,
    { Name = "/aws/eks/${var.cluster_name}/cluster" }
  )
}

resource "aws_eks_access_entry" "access_entry" {
  for_each = { for k, v in local.merged_access_entries : k => v if local.create }

  cluster_name      = aws_eks_cluster.cluster[0].name
  kubernetes_groups = try(each.value.kubernetes_groups, null)
  principal_arn     = each.value.principal_arn
  type              = try(each.value.type, "STANDARD")
  user_name         = try(each.value.user_name, null)

  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_access_policy_association" "association" {
  for_each = { for k, v in local.flattened_access_entries : "${v.entry_key}_${v.pol_key}" => v if local.create }

  access_scope {
    namespaces = try(each.value.association_access_scope_namespaces, [])
    type       = each.value.association_access_scope_type
  }

  cluster_name = aws_eks_cluster.cluster[0].name

  policy_arn    = each.value.association_policy_arn
  principal_arn = each.value.principal_arn

  depends_on = [
    aws_eks_access_entry.access_entry,
  ]
}

module "kms" {
  source  = "sudo-terraform-aws-modules/sudo-kms/aws"
  version = "1.0.1"

  create = local.create && var.create_kms_key && local.enable_cluster_encryption_config

  description             = coalesce(var.kms_key_description, "${var.cluster_name} cluster encryption key")
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.enable_kms_key_rotation

  # Policy
  enable_default_policy     = var.kms_key_enable_default_policy
  key_owners                = var.kms_key_owners
  key_administrators        = coalescelist(var.kms_key_administrators, [data.aws_iam_session_context.current.issuer_arn])
  key_users                 = concat([local.cluster_role], var.kms_key_users)
  key_service_users         = var.kms_key_service_users
  source_policy_documents   = var.kms_key_source_policy_documents
  override_policy_documents = var.kms_key_override_policy_documents

  # Aliases
  aliases = var.kms_key_aliases

  tags = merge(
    { terraform-aws-modules = "eks" },
    var.tags,
  )
}

data "aws_iam_policy_document" "assume_role_policy" {
  count = local.create && var.create_iam_role ? 1 : 0

  statement {
    sid     = "EKSClusterAssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "role" {
  count = local.create_iam_role ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}${var.prefix_separator}" : null
  path        = var.iam_role_path
  description = var.iam_role_description

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy[0].json
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = true

  # https://github.com/terraform-aws-modules/terraform-aws-eks/issues/920
  # Resources running on the cluster are still generating logs when destroying the module resources
  # which results in the log group being re-created even after Terraform destroys it. Removing the
  # ability for the cluster role to create the log group prevents this log group from being re-created
  # outside of Terraform due to services still generating logs during destroy process
  dynamic "inline_policy" {
    for_each = var.create_cloudwatch_log_group ? [1] : []
    content {
      name = local.iam_role_name

      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action   = ["logs:CreateLogGroup"]
            Effect   = "Deny"
            Resource = "*"
          },
        ]
      })
    }
  }

  tags = merge(var.tags, var.iam_role_tags)
}

# Minimal Custom Policy as per https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html
resource "aws_iam_policy" "cluster" {
  count = local.create_iam_role ? 1 : 0

  name        = var.cluster_policy_use_name_prefix ? null : local.cluster_policy_name
  name_prefix = var.cluster_policy_use_name_prefix ? local.cluster_policy_name : null
  description = var.cluster_policy_description
  path        = var.cluster_policy_path

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateTags"
        ],
        "Resource" : "arn:aws:ec2:*:*:instance/*",
        "Condition" : {
          "ForAnyValue:StringLike" : {
            "aws:TagKeys" : "kubernetes.io/cluster/*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeVpcs",
          "ec2:DescribeDhcpOptions",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      }
    ]
  })

  tags = merge(var.tags, var.cluster_policy_tags)
}
resource "aws_iam_role_policy_attachment" "cluster_policy_attachment" {
  count = local.create_iam_role ? 1 : 0

  policy_arn = aws_iam_policy.cluster[0].arn
  role       = aws_iam_role.role[0].name
}
resource "aws_iam_role_policy_attachment" "cluster" {
  for_each = { for k, v in {
    AmazonEKSVPCResourceController = "${local.iam_role_policy_prefix}/AmazonEKSVPCResourceController",
  } : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.role[0].name
}

resource "aws_iam_role_policy_attachment" "additional" {
  for_each = { for k, v in var.iam_role_additional_policies : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.role[0].name
}

# Using separate attachment due to `The "for_each" value depends on resource attributes that cannot be determined until apply`
resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  policy_arn = aws_iam_policy.cluster_encryption[0].arn
  role       = aws_iam_role.role[0].name
}

resource "aws_iam_policy" "cluster_encryption" {
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  name        = var.cluster_encryption_policy_use_name_prefix ? null : local.cluster_encryption_policy_name
  name_prefix = var.cluster_encryption_policy_use_name_prefix ? local.cluster_encryption_policy_name : null
  description = var.cluster_encryption_policy_description
  path        = var.cluster_encryption_policy_path

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey",
        ]
        Effect   = "Allow"
        Resource = var.create_kms_key ? module.kms.key_arn : var.cluster_encryption_config.provider_key_arn
      },
    ]
  })

  tags = merge(var.tags, var.cluster_encryption_policy_tags)
}


resource "aws_security_group" "cluster" {
  count = local.create_cluster_sg ? 1 : 0

  name        = var.cluster_security_group_use_name_prefix ? null : local.cluster_sg_name
  name_prefix = var.cluster_security_group_use_name_prefix ? "${local.cluster_sg_name}${var.prefix_separator}" : null
  description = var.cluster_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    { "Name" = local.cluster_sg_name },
    var.cluster_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "cluster" {
  for_each = { for k, v in merge(
    local.cluster_security_group_rules,
    var.cluster_security_group_additional_rules
  ) : k => v if local.create_cluster_sg }

  # Required
  security_group_id = aws_security_group.cluster[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_node_security_group, false) ? local.node_security_group_id : lookup(each.value, "source_security_group_id", null)
}

data "tls_certificate" "root_ca" {
  count = local.create_oidc_provider && var.include_oidc_root_ca_thumbprint ? 1 : 0

  url = aws_eks_cluster.cluster[0].identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  count = local.create_oidc_provider ? 1 : 0

  client_id_list  = distinct(compact(concat(["sts.amazonaws.com"], var.openid_connect_audiences)))
  thumbprint_list = concat(local.oidc_root_ca_thumbprint, var.custom_oidc_thumbprints)
  url             = aws_eks_cluster.cluster[0].identity[0].oidc[0].issuer

  tags = merge(
    { Name = "${local.name}-eks-irsa" },
    var.tags
  )
}

data "aws_eks_addon_version" "addon" {
  for_each = { for k, v in var.cluster_addons : k => v if local.create }

  addon_name         = try(each.value.name, each.key)
  kubernetes_version = coalesce(var.cluster_version, aws_eks_cluster.cluster[0].version)
  most_recent        = try(each.value.most_recent, null)
}

resource "aws_eks_addon" "addon" {
  for_each = { for k, v in var.cluster_addons : k => v if !try(v.before_compute, false) && local.create }

  cluster_name = aws_eks_cluster.cluster[0].name
  addon_name   = try(each.value.name, each.key)

  addon_version               = coalesce(try(each.value.addon_version, null), data.aws_eks_addon_version.addon[each.key].version)
  configuration_values        = try(each.value.configuration_values, null)
  preserve                    = try(each.value.preserve, true)
  resolve_conflicts_on_create = try(each.value.resolve_conflicts_on_create, "OVERWRITE")
  resolve_conflicts_on_update = try(each.value.resolve_conflicts_on_update, "OVERWRITE")
  service_account_role_arn    = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  depends_on = [
    module.fargate_profile,
    module.eks_managed_node_group,
  ]

  tags = merge(var.tags, try(each.value.tags, {}))
}


resource "aws_eks_identity_provider_config" "identity_provider" {
  for_each = { for k, v in var.cluster_identity_providers : k => v if local.create }

  cluster_name = aws_eks_cluster.cluster[0].name

  oidc {
    client_id                     = each.value.client_id
    groups_claim                  = lookup(each.value, "groups_claim", null)
    groups_prefix                 = lookup(each.value, "groups_prefix", null)
    identity_provider_config_name = try(each.value.identity_provider_config_name, each.key)
    issuer_url                    = try(each.value.issuer_url, aws_eks_cluster.cluster[0].identity[0].oidc[0].issuer)
    required_claims               = lookup(each.value, "required_claims", null)
    username_claim                = lookup(each.value, "username_claim", null)
    username_prefix               = lookup(each.value, "username_prefix", null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}


# This sleep resource is used to provide a timed gap between the cluster creation and the downstream dependencies
# that consume the outputs from here. Any of the values that are used as triggers can be used in dependencies
# to ensure that the downstream resources are created after both the cluster is ready and the sleep time has passed.
# This was primarily added to give addons that need to be configured BEFORE data plane compute resources
# enough time to create and configure themselves before the data plane compute resources are created.
resource "time_sleep" "sleep" {
  count = var.create ? 1 : 0

  create_duration = var.dataplane_wait_duration

  triggers = {
    cluster_name         = aws_eks_cluster.cluster[0].name
    cluster_endpoint     = aws_eks_cluster.cluster[0].endpoint
    cluster_version      = aws_eks_cluster.cluster[0].version
    cluster_service_cidr = var.cluster_ip_family == "ipv6" ? try(local.kubernetes_network_config.service_ipv6_cidr, "") : try(local.kubernetes_network_config.service_ipv4_cidr, "")

    cluster_certificate_authority_data = aws_eks_cluster.cluster[0].certificate_authority[0].data
  }
}


resource "aws_security_group" "node" {
  count = local.create_node_sg ? 1 : 0

  name        = var.node_security_group_use_name_prefix ? null : local.node_sg_name
  name_prefix = var.node_security_group_use_name_prefix ? "${local.node_sg_name}${var.prefix_separator}" : null
  description = var.node_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      "Name"                                = local.node_sg_name
      "kubernetes.io/cluster/${local.name}" = "owned"
    },
    var.node_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "node" {
  for_each = { for k, v in merge(
    local.efa_security_group_rules,
    local.node_security_group_rules,
    local.node_security_group_recommended_rules,
    var.node_security_group_additional_rules,
  ) : k => v if local.create_node_sg }

  # Required
  security_group_id = aws_security_group.node[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", [])
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_cluster_security_group, false) ? local.cluster_security_group_id : lookup(each.value, "source_security_group_id", null)
}


module "fargate_profile" {
  source = "./modules/fargate-profile"

  for_each = { for k, v in var.fargate_profiles : k => v if var.create }

  create = try(each.value.create, true)

  # Fargate Profile
  cluster_name      = time_sleep.sleep[0].triggers["cluster_name"]
  cluster_ip_family = var.cluster_ip_family
  name              = try(each.value.name, each.key)
  subnet_ids        = try(each.value.subnet_ids, var.fargate_profile_defaults.subnet_ids, var.subnet_ids)
  selectors         = try(each.value.selectors, var.fargate_profile_defaults.selectors, [])
  timeouts          = try(each.value.timeouts, var.fargate_profile_defaults.timeouts, {})

  # IAM role
  create_iam_role               = try(each.value.create_iam_role, var.fargate_profile_defaults.create_iam_role, true)
  iam_role_arn                  = try(each.value.iam_role_arn, var.fargate_profile_defaults.iam_role_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.fargate_profile_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.fargate_profile_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.fargate_profile_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.fargate_profile_defaults.iam_role_description, "Fargate profile IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.fargate_profile_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.fargate_profile_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.fargate_profile_defaults.iam_role_attach_cni_policy, true)
  # To better understand why this `lookup()` logic is required, see:
  # https://github.com/hashicorp/terraform/issues/31646#issuecomment-1217279031
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.fargate_profile_defaults, "iam_role_additional_policies", {}))

  tags = merge(var.tags, try(each.value.tags, var.fargate_profile_defaults.tags, {}))
}


module "eks_managed_node_group" {
  source = "./modules/eks-managed-node-group"

  for_each = { for k, v in var.eks_managed_node_groups : k => v if var.create }

  create = try(each.value.create, true)

  cluster_name    = time_sleep.sleep[0].triggers["cluster_name"]
  cluster_version = try(each.value.cluster_version, var.eks_managed_node_group_defaults.cluster_version, time_sleep.sleep[0].triggers["cluster_version"])

  # EKS Managed Node Group
  name            = try(each.value.name, each.key)
  use_name_prefix = try(each.value.use_name_prefix, var.eks_managed_node_group_defaults.use_name_prefix, true)

  subnet_ids = try(each.value.subnet_ids, var.eks_managed_node_group_defaults.subnet_ids, var.subnet_ids)

  min_size     = try(each.value.min_size, var.eks_managed_node_group_defaults.min_size, 1)
  max_size     = try(each.value.max_size, var.eks_managed_node_group_defaults.max_size, 3)
  desired_size = try(each.value.desired_size, var.eks_managed_node_group_defaults.desired_size, 1)

  ami_id                         = try(each.value.ami_id, var.eks_managed_node_group_defaults.ami_id, "")
  ami_type                       = try(each.value.ami_type, var.eks_managed_node_group_defaults.ami_type, null)
  ami_release_version            = try(each.value.ami_release_version, var.eks_managed_node_group_defaults.ami_release_version, null)
  use_latest_ami_release_version = try(each.value.use_latest_ami_release_version, var.eks_managed_node_group_defaults.use_latest_ami_release_version, false)

  capacity_type        = try(each.value.capacity_type, var.eks_managed_node_group_defaults.capacity_type, null)
  disk_size            = try(each.value.disk_size, var.eks_managed_node_group_defaults.disk_size, null)
  force_update_version = try(each.value.force_update_version, var.eks_managed_node_group_defaults.force_update_version, null)
  instance_types       = try(each.value.instance_types, var.eks_managed_node_group_defaults.instance_types, null)
  labels               = try(each.value.labels, var.eks_managed_node_group_defaults.labels, null)

  remote_access = try(each.value.remote_access, var.eks_managed_node_group_defaults.remote_access, {})
  taints        = try(each.value.taints, var.eks_managed_node_group_defaults.taints, {})
  update_config = try(each.value.update_config, var.eks_managed_node_group_defaults.update_config, local.default_update_config)
  timeouts      = try(each.value.timeouts, var.eks_managed_node_group_defaults.timeouts, {})

  # User data
  platform                   = try(each.value.platform, var.eks_managed_node_group_defaults.platform, "linux")
  cluster_endpoint           = try(time_sleep.sleep[0].triggers["cluster_endpoint"], "")
  cluster_auth_base64        = try(time_sleep.sleep[0].triggers["cluster_certificate_authority_data"], "")
  cluster_ip_family          = var.cluster_ip_family
  cluster_service_cidr       = try(time_sleep.sleep[0].triggers["cluster_service_cidr"], "")
  enable_bootstrap_user_data = try(each.value.enable_bootstrap_user_data, var.eks_managed_node_group_defaults.enable_bootstrap_user_data, false)
  pre_bootstrap_user_data    = try(each.value.pre_bootstrap_user_data, var.eks_managed_node_group_defaults.pre_bootstrap_user_data, "")
  post_bootstrap_user_data   = try(each.value.post_bootstrap_user_data, var.eks_managed_node_group_defaults.post_bootstrap_user_data, "")
  bootstrap_extra_args       = try(each.value.bootstrap_extra_args, var.eks_managed_node_group_defaults.bootstrap_extra_args, "")
  user_data_template_path    = try(each.value.user_data_template_path, var.eks_managed_node_group_defaults.user_data_template_path, "")
  cloudinit_pre_nodeadm      = try(each.value.cloudinit_pre_nodeadm, var.eks_managed_node_group_defaults.cloudinit_pre_nodeadm, [])
  cloudinit_post_nodeadm     = try(each.value.cloudinit_post_nodeadm, var.eks_managed_node_group_defaults.cloudinit_post_nodeadm, [])

  # Launch Template
  create_launch_template                 = try(each.value.create_launch_template, var.eks_managed_node_group_defaults.create_launch_template, true)
  use_custom_launch_template             = try(each.value.use_custom_launch_template, var.eks_managed_node_group_defaults.use_custom_launch_template, true)
  launch_template_id                     = try(each.value.launch_template_id, var.eks_managed_node_group_defaults.launch_template_id, "")
  launch_template_name                   = try(each.value.launch_template_name, var.eks_managed_node_group_defaults.launch_template_name, each.key)
  launch_template_use_name_prefix        = try(each.value.launch_template_use_name_prefix, var.eks_managed_node_group_defaults.launch_template_use_name_prefix, true)
  launch_template_version                = try(each.value.launch_template_version, var.eks_managed_node_group_defaults.launch_template_version, null)
  launch_template_default_version        = try(each.value.launch_template_default_version, var.eks_managed_node_group_defaults.launch_template_default_version, null)
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, var.eks_managed_node_group_defaults.update_launch_template_default_version, true)
  launch_template_description            = try(each.value.launch_template_description, var.eks_managed_node_group_defaults.launch_template_description, "Custom launch template for ${try(each.value.name, each.key)} EKS managed node group")
  launch_template_tags                   = try(each.value.launch_template_tags, var.eks_managed_node_group_defaults.launch_template_tags, {})
  tag_specifications                     = try(each.value.tag_specifications, var.eks_managed_node_group_defaults.tag_specifications, ["instance", "volume", "network-interface"])

  ebs_optimized           = try(each.value.ebs_optimized, var.eks_managed_node_group_defaults.ebs_optimized, null)
  key_name                = try(each.value.key_name, var.eks_managed_node_group_defaults.key_name, null)
  disable_api_termination = try(each.value.disable_api_termination, var.eks_managed_node_group_defaults.disable_api_termination, null)
  kernel_id               = try(each.value.kernel_id, var.eks_managed_node_group_defaults.kernel_id, null)
  ram_disk_id             = try(each.value.ram_disk_id, var.eks_managed_node_group_defaults.ram_disk_id, null)

  block_device_mappings              = try(each.value.block_device_mappings, var.eks_managed_node_group_defaults.block_device_mappings, {})
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, var.eks_managed_node_group_defaults.capacity_reservation_specification, {})
  cpu_options                        = try(each.value.cpu_options, var.eks_managed_node_group_defaults.cpu_options, {})
  credit_specification               = try(each.value.credit_specification, var.eks_managed_node_group_defaults.credit_specification, {})
  elastic_gpu_specifications         = try(each.value.elastic_gpu_specifications, var.eks_managed_node_group_defaults.elastic_gpu_specifications, {})
  elastic_inference_accelerator      = try(each.value.elastic_inference_accelerator, var.eks_managed_node_group_defaults.elastic_inference_accelerator, {})
  enclave_options                    = try(each.value.enclave_options, var.eks_managed_node_group_defaults.enclave_options, {})
  instance_market_options            = try(each.value.instance_market_options, var.eks_managed_node_group_defaults.instance_market_options, {})
  license_specifications             = try(each.value.license_specifications, var.eks_managed_node_group_defaults.license_specifications, {})
  metadata_options                   = try(each.value.metadata_options, var.eks_managed_node_group_defaults.metadata_options, local.metadata_options)
  enable_monitoring                  = try(each.value.enable_monitoring, var.eks_managed_node_group_defaults.enable_monitoring, true)
  enable_efa_support                 = try(each.value.enable_efa_support, var.eks_managed_node_group_defaults.enable_efa_support, false)
  create_placement_group             = try(each.value.create_placement_group, var.eks_managed_node_group_defaults.create_placement_group, false)
  placement_group_strategy           = try(each.value.placement_group_strategy, var.eks_managed_node_group_defaults.placement_group_strategy, "cluster")
  network_interfaces                 = try(each.value.network_interfaces, var.eks_managed_node_group_defaults.network_interfaces, [])
  placement                          = try(each.value.placement, var.eks_managed_node_group_defaults.placement, {})
  maintenance_options                = try(each.value.maintenance_options, var.eks_managed_node_group_defaults.maintenance_options, {})
  private_dns_name_options           = try(each.value.private_dns_name_options, var.eks_managed_node_group_defaults.private_dns_name_options, {})

  # IAM role
  create_iam_role               = try(each.value.create_iam_role, var.eks_managed_node_group_defaults.create_iam_role, true)
  iam_role_arn                  = try(each.value.iam_role_arn, var.eks_managed_node_group_defaults.iam_role_arn, null)
  iam_role_name                 = try(each.value.iam_role_name, var.eks_managed_node_group_defaults.iam_role_name, null)
  iam_role_use_name_prefix      = try(each.value.iam_role_use_name_prefix, var.eks_managed_node_group_defaults.iam_role_use_name_prefix, true)
  iam_role_path                 = try(each.value.iam_role_path, var.eks_managed_node_group_defaults.iam_role_path, null)
  iam_role_description          = try(each.value.iam_role_description, var.eks_managed_node_group_defaults.iam_role_description, "EKS managed node group IAM role")
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, var.eks_managed_node_group_defaults.iam_role_permissions_boundary, null)
  iam_role_tags                 = try(each.value.iam_role_tags, var.eks_managed_node_group_defaults.iam_role_tags, {})
  iam_role_attach_cni_policy    = try(each.value.iam_role_attach_cni_policy, var.eks_managed_node_group_defaults.iam_role_attach_cni_policy, true)
  # To better understand why this `lookup()` logic is required, see:
  # https://github.com/hashicorp/terraform/issues/31646#issuecomment-1217279031
  iam_role_additional_policies = lookup(each.value, "iam_role_additional_policies", lookup(var.eks_managed_node_group_defaults, "iam_role_additional_policies", {}))

  # Autoscaling group schedule
  create_schedule = try(each.value.create_schedule, var.eks_managed_node_group_defaults.create_schedule, true)
  schedules       = try(each.value.schedules, var.eks_managed_node_group_defaults.schedules, {})

  # Security group
  vpc_security_group_ids            = compact(concat([local.node_security_group_id], try(each.value.vpc_security_group_ids, var.eks_managed_node_group_defaults.vpc_security_group_ids, [])))
  cluster_primary_security_group_id = try(each.value.attach_cluster_primary_security_group, var.eks_managed_node_group_defaults.attach_cluster_primary_security_group, false) ? aws_eks_cluster.cluster[0].vpc_config[0].cluster_security_group_id : null

  tags = merge(var.tags, try(each.value.tags, var.eks_managed_node_group_defaults.tags, {}))
}
