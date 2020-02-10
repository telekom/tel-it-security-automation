<!---
tel-it-security-automation :- Ansible roles for automated security hardening.  
Copyright (c) 2019 Markus Schumburg, [...] Deutsche Telekom AG 
contact: devsecops@telekom.de 
This file is distributed under the conditions of the Apache-2.0 license. 
For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.
--->

# Telekom IT Security Automation - Hardening SSH
<img align="right" src="images/logo-cop-&-car-200x200.png" alt="Telekom IT DevSecOps Team" height="100" width="100">

Author: DevSecOps Team   

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](devsecops@telekom.de)

---

## Description

This Ansible role can be used to implement hardening of Linux OS on servers. The hardening will be done following the security requirements for SSH (3.04) from Telekom Security (see [References](#references) for used document version).

>**IMPORTANT**  
The playbook disables all SSH access without public-key. A user with public key and root privileges must exist on the system. Otherwise, remote login with SSH is not longer possible!

## Supported Platforms

Ansible control node & managed node requirements:
- Ansible version: 2.8
- Python version: 2.7 or version: 3.5 (or higher)

The role is tested with OpenSSH Version > `7.4` and with the following Linux versions:

  - Ubuntu 16.04 LTS
  - Ubuntu 18.04 LTS
  - RedHat Enterprise Linux 7
  - RedHat Enterprise Linux 8
  - CentOS 7
  - Amazon Linux 2
  - Suse Linux Enterprise Server 12
  - Suse Linux Enterprise Server 15

## Ansible Installation

See [Ansible Installation Guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for further details.

## Preconditions to use Ansible

Ansible is agent-free. This means no agent is needed on systems that should be configured with Ansible. But Ansible uses Python. Python must be installed on the control node and also on the managed node!

Ansible uses SSH to connect to remote systems. To connect and to perform all tasks a user is needed on the system that should be hardened. This user needs root privileges and must be member of sudo group. Needed parameters for the user can be defined in inventory or playbook file (see next chapter).

>**IMPORTANT**
Don't use user `root` to execute this role. The role will disable local and remote login via SSH for user `root`! Create your own user with root rights and sudo group membership.

## Inventory

Ansible by default uses the `/etc/ansible/hosts` file to specify hosts and
needed parameters.

To use your own `hosts` file use:
```console
$ ansible-playbook -i <location-of-host-file> <playbook>.yml
```

Example of 'hosts' file:
```yml
[test-system]
test ansible_host=127.0.0.1

[test-system:vars]
ansible_port=2222
ansible_user=vagrant
ansible_ssh_pass=vagrant
```

This is fine for testing purposes. In case of productive environments a dynamic inventory triggered by the used orchestration should be used.

More information:
* [Intro to Ansible inventory](http://docs.ansible.com/ansible/latest/intro_inventory.html)
* [Dynamic Inventory](http://docs.ansible.com/ansible/latest/intro_dynamic_inventory.html)

## Role

The downloaded role must be stored in the directory for Ansible roles on the Ansible control node. The default path to store roles is `/etc/ansible/roles`. In the file `/etc/ansible/ansible.cfg` with variable `roles_path` an own path can be
specified.

Example:
```console
roles_path    = ~/roles
```

## Variables

The default variables are located in the file `/default/main.yml`. Before
execution of the playbook please change this variables following the demands of the systems you like to harden.

| Name                | Req. | Values [*default*] | Description  |
|---------------------|:----:|--------------------|--------------|
| `ssh_server_ports`  | - | [*22*] | TCP Port(s) to use with SSH daemon. 
| `config_ipv6_enable`| - | true, [*false*] | Enable/disable the use of IPv6 with SSH. |
| `config_mgmt_interface_ipv4`| 25* | true, [*false*] | Enable/disable if a dedicated IPv4 management interface is used. |
| `mgmt_interface_ipv4`| 25* | - | IPv4 addresses for management interface. |
| `config_mgmt_interface_ipv6`| 25* | true, [*false*] | Enable/disable if a dedicated IPv6 management interface is used. |
| `mgmt_interface_ipv6`| 25* | - | IPv6 addresses for management interface. |
| `config_new_user` | 22* | true, [*false*] | Enable/disable if a user with root privileges and public key authentication should be generated for SSH. |
| `user_name` | 22* | - | Name of user to be configured for SSH login . |
| `public_key_file` | 22* | [*{{ role_path }}/files/id_rsa.pub*] | Location of public key that should be used for SSH user. |
| `group_sudo` | 22* | [*sudo*] | Group(s) to which the SSH user should be added. |

(*)The named requirements are coming from the Telekom Security document `3.65: Security Requirements for Linux for Servers`. There are also valid to be used with SSH!

Additional variables are located in the following files in directory `/vars`:

```
vars\__
       |_main.yml
       |_vars_ssh(01)ssh-requirements.yml
       |_vars_os_amazon_2.yml
       |_vars_os_redhat_7.yml
       |_vars_os_redhat_8.yml
       |_vars_os_suse_12.yml
       |_vars_os_suse_15.yml
       |_vars_os_ubuntu-16.yml
       |_vars_os_ubuntu-18.yml
```

> **NOTE** 
Changing variables in these files can affect security compliance and must be approved by your responsible Project Security Manager from Telekom Security!

## Execution of Playbook

Example of playbook:
```yml
---

- hosts: test-system
  become: true    # Become root (sudo)
  roles:
    - hardening-ssh
```

Start playbook with:

```console
$ ansible-playbook <playbook>.yml
```

You can also start the playbook with `ansible-playbook <playbook>.yml --check` to perform a dry-run. This is only a simulation without changing anything on the managed system. This can be used to perform compliance checks to detect if something has changed after successful system hardening. 

## References

Telekom Security - Security Requirements:
- SecReq 3.04: SSH (version 2.6; 01.12.2019)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
