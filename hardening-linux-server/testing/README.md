<!---
# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2019 Markus Schumburg, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.
--->

## DTIT DevSecOps Team - Shell Script - SSH Compliance Testing
---
<br>
<img align="right" src="../images/logo-cop-&-car-200x200.png" alt="Telekom IT DevSecOps Team" height="100" width="100">

Author : Markus Schumburg (DevSecOps Team)

Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)

E-Mail: [devsecops@telekom.de](devsecops@telekom.de)

---

## Description

The bash scripts can be used to check compliance for the following security
requirements of Deutsche Telekom AG:

- SecReq 3.65: Linux OS for Servers

## Platforms

The scripts are tested on systems with the following Linux OSes for servers.

- Ubuntu 16.04 LTS
- Ubuntu 18.04 LTS
- RedHat Enterprise Linux 7.x
- RedHat Enterprise Linux 8.x
- CentOS Linux 7.x
- Amazon Linux (Version 2)
- Suse Linux Enterprise Server 12
- Suse Linux Enterprise Server 15

Other Linux versions may work also but they are not tested now.

## Execute

The scripts must be executed with root rights on the system itself to check compliance.

$ sudo ./check_linux.sh

The script will use bash commands like grep, awk, sed, ss etc. It will not change or manipulate anything on the system. Two output files will be generated in the directory were the scripts are executed:

Log file: compliance-linux-[date].log

This file will include the results of the performed tests and show if they are PASSED or FAILED.

SoC file (csv): compliance-linux-[date].csv

This file will include the compliance statements (compliant, partly compliant, not compliant) for all requirements.

## References

Telekom Security - Security Requirements:
- SecReq 3.65: Linux OS for Servers (v1.3)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
