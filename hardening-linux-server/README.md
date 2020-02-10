<!---
tel-it-security-automation :- Ansible roles for automated security hardening.  
Copyright (c) 2019 Markus Schumburg, [...] Deutsche Telekom AG 
contact: devsecops@telekom.de 
This file is distributed under the conditions of the Apache-2.0 license. 
For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.
--->

# Telekom IT Security Automation - Hardening Linux Server
<img align="right" src="images/logo-cop-&-car-200x200.png" alt="Telekom IT DevSecOps Team" height="100" width="100">

Author: DevSecOps Team   

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](devsecops@telekom.de)

---

## Description

This Ansible role can be used to implement hardening of Linux OS on servers. The hardening will be done following the security requirements for Linux servers (3.65) from Telekom Security (see [References](#references) for used document version).

## Supported Platforms

Ansible control node & managed node requirements:
- Ansible version: 2.8 (or higher)
- Python version: 2.7 or version: 3.5 (or higher)

The role is tested with the following Linux versions:

  - Ubuntu 16.04 LTS
  - Ubuntu 18.04 LTS
  - RedHat Enterprise Linux 7
  - RedHat Enterprise Linux 8
  - CentOS 7
  - Amazon Linux 2
  - Suse Linux Enterprise Server 12
  - Suse Linux Enterprise Server 15

> **IMPORTANT:** This role only supports Linux versions for SERVERS! The role is not tested with desktop systems and can cause unexpected malfunctions.

## Ansible Installation

See [Ansible Installation Guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for further details.

## Preconditions to use Ansible

Ansible is agent-free. This means no agent is needed on systems that should be configured with Ansible. But Ansible uses python. Python must be installed on the control node and also on the managed node!

Ansible uses SSH to connect to remote systems. To connect and to perform all tasks a user is needed on the system that should be hardened. This user needs root privileges and must be member of sudo group. Needed parameters for the user can be defined in inventory or playbook file (see next chapter).

>**IMPORTANT** 
Don't use user `root` to execute this role. The role will disable local and remote login via SSH for user `root`! Create your own user with root
rights and sudo group membership.

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

The default variables are located normally in the file `/default/main.yml`. We don't use this file! To give more flexibility we us our own
default file named `/vars/var_linux_default_settings.yml`. 

As an alternative copy the file `var_linux_default_settings.yml` in directory `/vars` and rename it `var_linux_user_settings.yml` to create your own configuration.

Edit this file to change the variables to enable/disable security requirements and set specific values for your own environment.

Variables in file `/vars/var_linux_default_settings.yml`:

| Name                | Req. | Values [*default*] | Description                       |
|-----------------------|:----:|--------------------|-----------------------------------|
| `config_req_NN`       | all  | [*true*], false    | Enable/disable requirements |
| `tcp_services`        | 02   | [*22*]    | Set allowed TCP ports. 22 (SSH) must be configured for Ansible to run. |
| `udp_services`        | 02   | - none -    | Set allowed UDP ports. |
| `allowed_users`       | 19   | - none -     | To configure users that should not be deleted during Ansible hardening. |
| `mgmt_interface_ipv4` | 25   | - none -     | Not implemented in current version. |
| `mgmt_interface_ipv6` | 25   | - none -     | Not implemented in current version. |
| `timesync_servers`    | 30   | - none -     | Set the IP address(es) for NTP servers to use with chrony. |
| `set_timezone`        | 30   | [*Europe/Berlin*]| Set timezone for system. |
| `syslog_type`         | 37   | [*rsyslog*]| Configure syslog solution to use. Note: only rsyslog is supported in this version. |
| `syslog_server`       | 39   | -none-   | Set the IP address(es) for syslog server. |
| `syslog_protocol`       | 39   | [*udp*], tcp | Set protocol to use for syslog (default is UDP). |
| `syslog_port`       | 39   | [*514*]| Set port to use with syslog service(default 514). |

Additional variables are located in the following files in directory `/vars`:

```
vars\__
       |_main.yml
       |_vars_linux(01)basic-hardening.yml
       |_vars_linux(02)logging.yml
       |_vars_linux(03)pluggable-authentication-modules.yml
       |_vars_linux(04)iptables.yml
       |_vars_linux(05)mandatory-access-control.yml
       |_vars_linux(06)compliance-checks.yml
       |_vars_os_amazon_2.yml
       |_vars_os_redhat_7.yml
       |_vars_os_redhat_8.yml
       |_vars_os_suse_12.yml
       |_vars_os_suse_15.yml
       |_vars_os_ubuntu-16.yml
       |_vars_os_ubuntu-18.yml
```

> **NOTE:** Changing variables in these files can affect security compliance and must be approved by your responsible Project Security Manager from Telekom Security!

-------------------------------------------------------------------------------

## Execution of Playbook

>**IMPORTANT** 
Before execution of the playbook it is important to configure the variables in the file `var_linux_default_settings.yml` or `var_linux_default_settings.yml` in directory `/var` with the specific values for your environment!

Example of playbook:
```yml
---

- hosts: test-system
  become: true    # Become root (sudo)
  roles:
    - hardening-linux-server
  post_tasks:
    - reboot:
      when: not ansible_check_mode
```

The `post_task:` is optional. But it is highly recommended to reboot the system after hardening with Ansible. This is especially necessary to activate changes for SELinux!

Start playbook with:

```console
$ ansible-playbook <playbook>.yml
```

You can also start the playbook with `ansible-playbook <playbook>.yml --check` to perform a dry-run. This is only a simulation without changing anything on the managed system. This can be used to perform compliance checks to detect if something has changed after successful system hardening. 

## References

Telekom Security - Security Requirements:
- SecReq 3.65: Linux OS for Servers (version 1.3; 01.12.2019)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
