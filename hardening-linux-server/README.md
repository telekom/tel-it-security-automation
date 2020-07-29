<!---
tel-it-security-automation :- Ansible roles for automated security hardening.  
Copyright (c) 2020 Maximilian Hertstein [...] Deutsche Telekom AG
contact: devsecops@telekom.de
This file is distributed under the conditions of the Apache-2.0 license.
For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.
--->

# Telekom IT Security Automation - Hardening Linux Server

Author: DevSecOps Team

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](mailto:devsecops@telekom.de)

---

## Description

This Ansible role can be used to implement hardening of Linux OS on servers. The hardening will be done following the security requirements for Linux servers (3.65) from Telekom Security (see [References](#references) for used document version).

The Ansible role can also be used to simulate the configuration with so named 'check mode'. In this case the system configuration will not be changed.  

### Supported Platforms

Ansible control node & managed node requirements:

- Ansible version: 2.9 (or higher)
- Python version: 3.5 (or higher)

The role is tested with the following Linux versions:

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

> **IMPORTANT:** This role only supports Linux versions for SERVERS! The role is not tested with desktop systems and can cause unexpected malfunctions.

### Supported Security Requirements

The following security requirements from Telekom Security SecReq 3.65 (Linux OS for Servers) are implemented ([x]: implemented; [-]: not implemented) in this Ansible role:

| No. | Requirement |     |  
|:---:|-------------|:---:|
| 01  | Unused services and protocols must be deactivated. | [x] |
| 02  | The reachability of services must be restricted. | [x] |
| 03  | Unused software must not be installed or must be uninstalled. | [x] |
| 04  | Dedicated partitions must be used for growing content that can influence the availability of the system. | [x] |
| 05  | Parameters nodev:  nosuid and noexec must be set for partitions where this is applicable. | [x] |
| 06  | Automounting must be disabled. | [x] |
| 07  | The use of at/cron must be restricted to authorized users. | [x] |
| 08  | Sticky bit must be set on all world-writable directories. | [x] |
| 09  | No regular files that are world writable must exist. | [x] |
| 10  | Passwords must be protected with an appropriate hashing function. | [x] |
| 11  | The default user umask must be 027 or more restrictive. | [x] |
| 12  | Not needed SUID and SGID bits must be removed from executables. | [x] |
| 13  | Core dumps must be disabled. | [x] |
| 14  | Protection against buffer overflows must be enabled. | [x] |
| 15  | IPv4 protocol stack must be securely configured. | [x] |
| 16  | IPv6 protocol stack must be securely configured. | [x] |
| 17  | Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse. | [x] |
| 18  | GPG check for repository server must be activated and corresponding keys for trustable repositories must be configured. | [x] |
| 19  | User accounts must be used that allow unambiguous identification of the user. | [x] |
| 20  | System accounts must be non-login. | [x] |
| 21  | User accounts must be protected against unauthorized use by at least one authentication attribute. | [x] |         |
| 22  | User accounts with extensive rights must be protected with two authentication attributes. | [-] | 
| 23  | The system must be connected to a central system for user administration. | [-] |
| 24  | Authentication must be used for single user mode. | [x] |
| 25  | The management of the operating system must be done via a dedicated management network. | [-] |
| 26  | Management services must be bound to the management network. | [-] |
| 27  | Encrypted protocols must be used for management access to administrate the operating system. | [-] |
| 28  | Auditing must be enabled at boot by setting a kernel parameter. | [x] |
| 29  | Log rotation for logfiles must be configured. | [x] |
| 30  | System time must be synchronized against a reference time source. | [x] |
| 31  | Auditd service must be used to log security relevant events. | [x] |
| 32  | System events must be logged. | [x] |
| 33  | Access and Authentication events must be logged. | [x] |
| 34  | Account and Group Management events must be logged. | [x] |
| 35  | Configuration Change events must be logged. | [x] |
| 36  | Auditd configuration must be immutable. | [x] |
| 37  | Security relevant logging data must be send to an external system direct after their creation. | [x] |
| 38  | If RSyslog is used, the default permission of 640 or more restrictive for logfiles must be configured. | [x] |
| 39  | If RSyslog is used, at least one central logging server must be configured. | [x] |
| 40  | If Syslog-NG is used, the default permission of 640 or more restrictive for logfiles must be configured. | [-] |
| 41  | If Syslog-NG is used, at least one central logging server must be configured. | [-] |
| 42  | If PAM is used, it needs to be reconfigured to use strong salted password hash functions while doing many calculation rounds to protect passwords. | [x] |
| 43  | If PAM is used, password rules must be configured for PAM to force the use of passwords with a minimum length of 12 characters and a combination of three out of the following categories: upper cases, lower case, numbers and special characters. | [x] |
| 44  | If PAM is used, a protection against brute force and dictionary attacks that hinder password guessing must be configured in PAM. | [x] |
| 45  | If PAM is used , PAM must be configured that motd did not contain any sensitive data. | [x] |
| 46  | If iptables is used, policies for loopback traffic must be configured. | [x] |
| 47  | If iptables is used, policies for outbound and established connections must be configured. | [x] |
| 48  | If iptables is used, policies must exist for all ports in listening state. | [x] |
| 49  | If iptables is used, the default policy for tables INPUT and FORWARD must be configured to drop all traffic. | [x] |
| 50  | If a system has Internet facing services or is a virtualization host, a MAC solution must be used to restrict these services respectively guest VMs. | [x] |
| 51  | If SELinux is used, it must not be disabled in bootloader configuration. | [x] |
| 52  | If SELinux is used, its state must be enforced. | [x] |
| 53  | If SELinux is used, the policy must be configured. | [x] |
| 54  | If SELinux is used, SETroubleshoot and MCS Translation Service must not be installed. | [x] |
| 55  | If AppArmor is used, it must not be disabled in bootloader configuration. | [x] |
| 56  | AppArmor is used, its state must be enforced. | [x] |
| 57  | No legacy + entries must exist in files passwd, shadows and group. | [x] |
| 58  | A user's home directory must be owned by the user and have mode 750 or more restrictive. | [x] |
| 59  | Default group for the root account must be GID 0. | [x] |
| 60  | Root must be the only UID 0 account. | [x] |
| 61  | All groups in /etc/passwd must exist in /etc/group. | [x] |
| 62  | No duplicate UIDs and GIDs must exist. | [x] |
| 63  | No duplicate user and group names must exist. | [x] |
| 64  | The shadow group must be empty (only Debian-based Linux distributions). | [x] |
| 65  | No files and directories without assigned user or group must exist. | [x] |
| 66  | Permissions of security relevant configuration files must have the distribution default values or more restrictive. | [x] |

## Ansible Usage

### Ansible Installation

See [Ansible Installation Guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for further details.

### Preconditions to use Ansible

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

- `vars_custom_linux.yml` (you can find an example file in `/vars`)
- `vars_custom_config.yml`
- `vars_user_config.yml`
- `vars_user_linux.yml`

Edit this file to change the variables to enable/disable security requirements and set specific values for your own environment. If no custom defined variables file exist the role will be executed with default parameters.

Variables in file `/vars/vars_custom_linux.yml`:

| Name                | Req. | Values [*default*] | Description                 |
|---------------------|:----:|--------------------|-----------------------------|
| `config_req_NN`     | all  | [*true*], false    | Enable/disable requirements |
| `tcp_services`      | 02   | [*22*]             | Set allowed TCP ports. 22 (SSH) must be configured for Ansible to run. |
| `udp_services`      | 02   | [*68*],[*123*]     | Set allowed UDP ports. |
| `allowed_users`     | 19   | - none -           | To configure users that should not be deleted during Ansible hardening. |
| `timesync_servers`  | 30   | - none -           | Set the IP address(es) for NTP servers to use with chrony. |
| `set_timezone`      | 30   | [*Europe/Berlin*]  | Set timezone for system. |
| `syslog_type`       | 37   | [*rsyslog*]        | Configure syslog solution to use. Note: only rsyslog is supported in this version. |
| `syslog_server`     | 39   | -none-             | Set the IP address(es) for syslog server. |
| `syslog_protocol`   | 39   | [*udp*], tcp       | Set protocol to use for syslog (default is UDP). |
| `syslog_port`       | 39   | [*514*]            | Set port to use with syslog service(default 514). |

Additional variables are located in the following files in directory `/vars`:

```console
vars\__
       |_main.yml
       |_vars_custom_linux.yml
       |_vars_os_amazon_2.yml
       |_vars_os_redhat_7.yml
       |_vars_os_redhat_8.yml
       |_vars_os_suse_12.yml
       |_vars_os_suse_15.yml
       |_vars_os_ubuntu-16.yml
       |_vars_os_ubuntu-18.yml
```

> **NOTE:** Changing variables in these files can affect security compliance and must be approved by your responsible Project Security Manager from Telekom Security!

### Execution of Playbook

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

This Ansible role Telekom Security - Security Requirements:

- SecReq 3.65: Linux OS for Servers (version 1.4; 01.07.2020)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
