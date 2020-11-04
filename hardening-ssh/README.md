<!---
tel-it-security-automation :- Ansible roles for automated security hardening.  
Copyright (c) 2020 Maximilian Hertstein, [...] Deutsche Telekom AG 
contact: devsecops@telekom.de 
This file is distributed under the conditions of the Apache-2.0 license. 
For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.
--->

# Telekom IT Security Automation - Hardening SSH

Author: DevSecOps Team

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](mailto:devsecops@telekom.de)

---

## Description

This Ansible role can be used to implement hardening of Linux OS on servers. The hardening will be done following the security requirements for SSH (3.04) from Telekom Security (see [References](#references) for used document version).

>**IMPORTANT**  
The playbook disables all SSH access without public-key. A user with public key and root privileges must exist on the system. Otherwise, remote login with SSH is not longer possible!

The Ansible role can also be used to simulate the configuration with so named 'check mode'. In this case the system configuration will not be changed. 

### Supported Platforms

Ansible control node & managed node requirements:

- Ansible version: 2.9
- Python version: 3.5 (or higher)

The role is tested with OpenSSH Version > `7.4` and with the following Linux versions:

- Ubuntu 16.04 LTS
- Ubuntu 18.04 LTS
- Ubuntu 20.04 LTS
- RedHat Enterprise Linux 7
- RedHat Enterprise Linux 8
- CentOS 7
- CentOS 8
- Amazon Linux 2
- Suse Linux Enterprise Server 12
- Suse Linux Enterprise Server 15

### Supported Security Requirements

The following security requirements from Telekom Security SecReq 3.03 (SSH) are implemented ([x]: implemented; [-]: not implemented) in this Ansible role:

| No. | Requirement |     |  
|:---:|-------------|:---:|
| 01  | Unused services and protocols must be deactivated. | [x] |

## Ansible Usage

### Ansible Installation

See [Ansible Installation Guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for further details.

### Preconditions to use Ansible

Ansible is agent-free. This means no agent is needed on systems that should be configured with Ansible. But Ansible uses Python. Python must be installed on the control node and also on the managed node!

Ansible uses SSH to connect to remote systems. To connect and to perform all tasks a user is needed on the system that should be hardened. This user needs root privileges and must be member of sudo group. Needed parameters for the user can be defined in inventory or playbook file (see next chapter).

>**IMPORTANT**
Don't use user `root` to execute this role. The role will disable local and remote login via SSH for user `root`! Create your own user with root rights and sudo group membership.

### Inventory

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

- [Intro to Ansible inventory](http://docs.ansible.com/ansible/latest/intro_inventory.html)
- [Dynamic Inventory](http://docs.ansible.com/ansible/latest/intro_dynamic_inventory.html)

### Role

The downloaded role must be stored in the directory for Ansible roles on the Ansible control node. The default path to store roles is `/etc/ansible/roles`. In the file `/etc/ansible/ansible.cfg` with variable `roles_path` an own path can be
specified.

Example:

```console
roles_path    = ~/roles
```

### Variables

The different tasks and their configurations can be configured with variables. Therefore, a file with customer defined variables must exist in folder `/vars`. Possible names for such a file are:

- `vars_custom_ssh.yml` (you can find an example file in `/vars`)
- `vars_custom_config.yml`
- `vars_user_config.yml`
- `vars_user_ssh.yml`

Edit this file to change the variables to enable/disable security requirements and set specific values for your own environment. If no custom defined variables file exist the role will be executed with default parameters.

Variables in file `/vars/vars_custom_ssh.yml`:

| Name                   | Req. | Values [*default*]         | Description  |
|------------------------|:----:|----------------------------|--------------|
| `ssh_server_ports`     | -    | [*22*]                     | Change if other port should be used |
| `ipv6_enable`          | -    | [*false*]                  | Enable if IPv6 should be used |
| `mgmt_interface_ipv4`  | -    | [*false*]                  | Enable (true) if a dedicated IPv4 management interface is used |
| `ipv4_mgmt_interface`  | -    | [*0.0.0.0*]                | Define IPv4 address for mgmt interface if needed |
| `mgmt_interface_ipv6`  | -    | [*false*]                  | Enable if (true) a dedicated IPv6 management interface is used |
| `ipv6_mgmt_interface`  | -    | [*::*]                     | Define IPv6 address for mgmt interface if needed|
| `new_ssh_user`         | -    | [*false*]                  | Enable if role should create a ssh user with root privileges.|
| `ssh_user_name`        | -    | -                          | Set user name if `new_ssh_user` is true |
| `ssh_public_key`       | -    | -                          | Set path/file name for public key if `new_ssh_user` is true. |
| `ssh_groups`           | -    | [*sudo*]                   | Change if other group is used for sudo if `new_ssh_user` is true |
| `ssh_config_req_NN`    | all  | [*true*], false            | Enable/disable requirements |
| `loglevel`             | 07   | -                          | Set loglevel for SSH logging |
| `deny_ssh_users`       | 16   | -                          |  |
| `allow_ssh_users`      | 16   | -                          |  |
| `deny_ssh_groups`      | 16   | -                          |  |
| `allow_ssh_groups`     | 16   | -                          |  |
| `client_alive_interval`| 17   | [*60*]                     | Set to configure timeout for SSH connection |
| `client_alive_count`   | 17   | [*10*]                     | Set to configure timeout for SSH connection |
| `authkeys_file`        | -    | [*.ssh/authorized_keys*]   | Change to set a different location of AuthorizedKeysFile  |
| `config_authkeys_cmd`  | -    | [*false*]                  | Enable to use AuthorizedKeysCommand function  |
| `authkeys_cmd`         | -    | [*/bin/false*]             | Change to the desired program to be used to look up the user's public keys  |
| `authkeys_cmd_usr`     | -    | [*nobody*]                 | Change to specify the user under whose account the AuthorizedKeysCommand is run |

Additional variables are located in the following files in directory `/vars`:

```console
vars\__
       |_main.yml
       |_vars_custom_ssh.yml
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

### Execution of Playbook

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

- SecReq 3.04: SSH (version 2.7, 01.07.2020)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
