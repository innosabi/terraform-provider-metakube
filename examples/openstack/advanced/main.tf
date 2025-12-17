terraform {
  required_providers {
    metakube = {
      source = "syseleven/metakube"
    }
    openstack = {
      source = "terraform-provider-openstack/openstack"
    }
  }
}

// You can download and source "OpenStack RC File v3" for your account at https://cloud.syseleven.de or configure it here.
// provider "openstack" {
//  auth_url = "https://keystone.cloud.syseleven.net:5000/v3"
//
//  user_name = var.username
//
//  password = var.password
//
//  tenant_name = var.tenant
//
//  domain_name = "Default"
// }

# Create cluster internal network.
resource "openstack_networking_network_v2" "network" {
  name           = var.cluster_network_name
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "subnet" {
  name        = var.subnet_name
  network_id  = openstack_networking_network_v2.network.id
  cidr        = "192.168.1.0/24"
  ip_version  = 4
  enable_dhcp = true
  allocation_pool {
    start = "192.168.1.2"
    end   = "192.168.1.254"
  }
  # Internal IPs of DNS Servers in the cloud.
  dns_nameservers = [
    "37.123.105.116",
    "37.123.105.117",
  ]
}

# Create openstack security for cluster internal network.
resource "openstack_networking_secgroup_v2" "sg" {
  name                 = "${var.cluster_name}-cluster-sg"
  description          = "Security group for Metakube cluster ${var.cluster_name}"
  delete_default_rules = false
}

## Allow all traffic within the security group (applies to all servers using this SG)
resource "openstack_networking_secgroup_rule_v2" "ingress_ipv4_within_group" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_group_id   = openstack_networking_secgroup_v2.sg.id
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "egress_ipv4_within_group" {
  direction         = "egress"
  ethertype         = "IPv4"
  remote_group_id   = openstack_networking_secgroup_v2.sg.id
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "ingress_ipv6_within_group" {
  direction         = "ingress"
  ethertype         = "IPv6"
  remote_group_id   = openstack_networking_secgroup_v2.sg.id
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "egress_ipv6_within_group" {
  direction         = "egress"
  ethertype         = "IPv6"
  remote_group_id   = openstack_networking_secgroup_v2.sg.id
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

#resource "openstack_networking_secgroup_rule_v2" "allow_ssh" {
#  direction         = "ingress"
#  ethertype         = "IPv4"
#  port_range_min    = 22
#  port_range_max    = 22
#  protocol          = "tcp"
#  security_group_id = openstack_networking_secgroup_v2.sg.id
#}

resource "openstack_networking_secgroup_rule_v2" "ingress_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "ingress_icmp6" {
  direction         = "ingress"
  ethertype         = "IPv6"
  protocol          = "ipv6-icmp"
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "ingress_tcp_node_ports" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 30000
  port_range_max    = 32767
  remote_ip_prefix  = openstack_networking_subnet_v2.subnet.cidr
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "ingress_udp_node_ports" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 30000
  port_range_max    = 32767
  remote_ip_prefix  = openstack_networking_subnet_v2.subnet.cidr
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

## Allow traffic to and from Kubernetes services and pods CIDR
resource "openstack_networking_secgroup_rule_v2" "ingress_kube_services_cidr" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = var.kube_services_cidr
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_networking_secgroup_rule_v2" "ingress_kube_pods_cidr" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = var.kube_pod_cidr
  security_group_id = openstack_networking_secgroup_v2.sg.id
}

resource "openstack_compute_servergroup_v2" "anti-affinity" {
  name     = "test-anti-affinity"
  policies = ["anti-affinity"]
}

# Set up a router to allow access through public internet.
data "openstack_networking_network_v2" "external" {
  name = var.floating_ip_pool
}
resource "openstack_networking_router_v2" "router_1" {
  name                = var.router_name
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external.id
}
resource "openstack_networking_router_interface_v2" "router_interface_1" {
  router_id = openstack_networking_router_v2.router_1.id
  subnet_id = openstack_networking_subnet_v2.subnet_1.id
}

# The latest Ubuntu 18.04 image available.
data "openstack_images_image_v2" "image" {
  most_recent = true

  visibility = "public"
  properties = {
    os_distro  = "ubuntu"
    os_version = "24.04"
  }
}

# Read local sshkey's public part and publish it to MetaKube.
data "local_file" "public_sshkey" {
  filename = pathexpand(var.public_sshkey_file)
}

resource "metakube_sshkey" "local" {
  project_id = var.project_id

  name       = "local SSH key"
  public_key = data.local_file.public_sshkey.content
}

data "metakube_k8s_version" "cluster" {
  major = "1"
  minor = "33"
}

resource "metakube_cluster" "cluster" {
  name       = var.cluster_name
  dc_name    = var.dc_name
  project_id = var.project_id

  sshkeys = [metakube_sshkey.local.id]


  # add labels
  labels = {
    "test-key" = "test-value"
  }

  spec {
    enable_ssh_agent = true
    version          = data.metakube_k8s_version.cluster.version
    cloud {
      openstack {
        user_credentials {
          project_id   = var.openstack_project_id
          project_name = var.openstack_project_name
          username     = var.username
          password     = var.password
        }
        floating_ip_pool = data.openstack_networking_network_v2.external.name
        security_group   = openstack_networking_secgroup_v2.sg.name
        network          = openstack_networking_network_v2.network.name
        subnet_id        = openstack_networking_subnet_v2.subnet.id
        subnet_cidr      = openstack_networking_subnet_v2.subnet.cidr
        server_group_id  = openstack_compute_servergroup_v2.anti-affinity.id
      }
    }

    cni_plugin {
      type    = "cilium"
    }

    # enable audit logging
    audit_logging       = true
    pod_node_selector   = true
    pod_security_policy = true
    services_cidr       = var.kube_services_cidr
    pods_cidr           = var.kube_pod_cidr
  }
}

# create admin.conf file
resource "local_file" "kubeconfig" {
  content  = metakube_cluster.cluster.kube_config
  filename = "${path.module}/admin.conf"
}

resource "metakube_node_deployment" "acctest_nd" {
  cluster_id = metakube_cluster.cluster.id
  name       = null # auto generate

  spec {
    min_replicas = var.node_min_replicas
    max_replicas = var.node_max_replicas

    template {
      labels = {
        key = "value"
      }

      cloud {
        openstack {
          flavor                       = var.node_flavor
          disk_size                    = var.node_disk_size
          image                        = var.node_image != null ? var.node_image : data.openstack_images_image_v2.image.name
          use_floating_ip              = var.use_floating_ip
          instance_ready_check_period  = "5s"
          instance_ready_check_timeout = "100s"
          tags = {
            foo = "bar"
          }
        }
      }
      operating_system {
        ubuntu {
          dist_upgrade_on_boot = true
        }
      }
      versions {
        kubelet = data.metakube_k8s_version.cluster.version
      }
    }
  }
}
