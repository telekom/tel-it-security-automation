# Security & Compliance Automation
<img align="right" src="images/logo-cop-&-car-200x200.png" alt="Telekom IT DevSecOps Team" height="100" width="100">

Author: DevSecOps Team   

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](devsecops@telekom.de)

-------------------------------------------------------------------------------

## Introduction

Software is delivered by vendors with a minimal pre-configuration that is feasible for most customers. This is also true for security relevant configuration which leads to insecure systems in default configuration. To change this an important job in IT security is the secure configuration of operating systems and applications - also named hardening. This is a complex and error-prone task if done manually. Additionally, this task must be repeated and controlled in case of any changes on a system.    

The DevSecOps team of Deutsche Telekom IT GmbH has the mission to deliver tools and solutions that help there customers to build secure application and services. The intention of DevSecOps teams project "Security & Compliance Automation" is the implementation of a solution for automated hardening and compliance checks that allow fast, reproducible and reliable implementation and documentation of security requirements for operating systems and applications.

## Solution

This project provides an automated solution to implement security hardening for operating systems and applications. This is needed to reach an adequate security level and to be compliant to the security requirements from Telekom Security. The solution helps to prepare systems that can easily pass the technical part of the Privacy & Assessment Process (PSA) of Telekom Security and Group Privacy.

![Automated Hardening](images/hardening-pipeline.png "Automated Hardening")

The scripts are developed in a way, that they can be used to automatically harden operating systems and applications. Additionally the roles can be used to perform compliance checks in Ansible check mode ("dry run").

## Roles

Two roles are currently available:

- Ansible role for hardening of Linux based Servers
- Ansible role for hardening of OpenSSH daemon on Linux

The hardening will be done following the security requirements for 
- Linux servers (3.65) 
- SSH (3.04)

from Telekom Security (see [References](#references) for used document versions).

## Supported Platforms

### Ansible control node requirements
- Ansible version: 2.8 (or higher)
- Python version: 2.7 or version: 3.5 (or higher)

### Managed node requirements

On managed node the following Python version must be installed:

- Python version: 2.7 or version: 3.5 (or higher)

The roles are tested for hardening of the following Linux versions:

  - Ubuntu 16.04 LTS
  - Ubuntu 18.04 LTS
  - RedHat Enterprise Linux 7
  - RedHat Enterprise Linux 8
  - CentOS 7
  - Amazon Linux 2
  - Suse Linux Enterprise Server 12
  - Suse Linux Enterprise Server 15

> **IMPORTANT:** These roles only supports Linux versions for SERVERS! The role is not tested with desktop systems and can cause unexpected malfunctions.

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

### Variables for Linux role

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
       |_var_linux_default_settings.yml
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

### Variables for SSH role

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

-------------------------------------------------------------------------------

## Execution of Playbook

>**IMPORTANT** 
For Ansible role for Linux: before execution of the playbook it is important to configure the variables in the file `var_linux_default_settings.yml` or `var_linux_default_settings.yml` in directory `/var` with the specific values for your environment!

Example of playbook:
```yml
---

- hosts: test-system
  become: true    # Become root (sudo)
  roles:
    - hardening-linux-server
    - hardening-ssh
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
- SecReq 3.04: SSH (version 2.6; 01.12.2019)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)



