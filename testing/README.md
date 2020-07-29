# Telekom IT Security Automation - Linux Compliance Testing

Authors: DTIT DevSecOps Team
  
Company: [Deutsche Telekom IT GmbH](https://www.telekom.com)
  
E-Mail: [devsecops@telekom.de](mailto:devsecops@telekom.de)

---

## Description

The shell script collection can be used to perform compliance testing for Linux based systems. They can be used in test stages in CI/CD pipelines and also to perform compliance checks direct on Linux based systems.

## Supported Platforms

The scripts are developed to run on Linux versions of RedHat, Debian and Suse Linux OS family. All scripts are tested on the following Linux operating systems:

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

Other Linux versions may work also but they are not tested.

## Script Files

For compliance testing three file types are available:

- test script
- start script
- custom variables script

These files are described in detail in the following chapters.

### Test Script

Test scripts (file: `test-<name>.sh`) include all compliance tests for security requirements for the Linux operating system or for an application. Available test scripts are:

- test_linux.sh (compliance tests for [SecReq 3.65 Linux OS for Server](#references))
- test_ssh.sh (compliance tests [SecReq 3.04 SSH](#references))

The script must be executed with root privileges.

```console
$ sudo ./test_linux.sh
```

The test script will print the test results to stdout. No output files will be generated! The test script can be used together with a variable script to define custom variables for test execution. How to use such a file is described in more detail in the chapter [Custom Variables Script](#custom-variables-script)

### Start Script

The start script (file: `start_testing.sh`) includes functions and features that are identical for all tests scripts. This script can be used to execute several test scripts one after the other. To use the start script in combination with one or several test scripts (and the optional variables scripts) they must be stored together in the same folder.

```console
[vagrant@localhost ~]$ pwd
/home/vagrant
[vagrant@localhost ~]$ ls -l
-rwx------. 1 vagrant vagrant   9555 10. Jun 12:03 start_testing.sh
-rwx------. 1 vagrant vagrant 123671 10. Jun 12:03 test_linux.sh
-rwx------. 1 vagrant vagrant  36166 10. Jun 12:03 test_ssh.sh
-rw-r--r--. 1 vagrant vagrant  10494 10. Jun 12:03 vars_custom_linux.sh
-rw-r--r--. 1 vagrant vagrant   4158 10. Jun 12:03 vars_custom_ssh.sh
```

The start_script has a help function. To show help execute it the following way:
```console
[vagrant@localhost ~]$ ./start_testing.sh -?

Usage: ./start_testing.sh [OPTIONS] -t [SCRIPT] -o [FILE]
Script for compliance testing on Linux based systems
Example: ./start_testing.sh -n -t <test-script> -o <output-file>
	-t   Define script with test cases. Otherwise all found scripts
	     in same folder as start script are executed.
	-o   Define name for output file for log data. (default name is
	    'test-log-<os><date>.log'). If file exists it will be overwritten
	-d   Use default variables and ignore variable files in folder.
	-x   Write no output files (log/soc).
	-n   No OS check will be performed.
	-q   Script runs in quite mode.
	-f   If test cases fail script will end with 0 and not 1 as
	     error code.
```

The start script must be executed with root privileges. Otherwise it will terminated promptly. If the script is executed as shown in the example the default setup will be launched. That means all found test scripts (inclusive variables files if available) will be execute one after the other. If the test script for Linux operating system (with name `test_linux.sh`) is available it will be execute
first!

```console
$ sudo ./start_testing.sh
```

Scripts call each other as shown next. This picture also shows the output files created during execution. The output files are described in subchapter [Output Files](#output-files)
```

  start_testing.sh
   |          |
   |          |__out__ `test-log-<os/os version>-(<date>).log`
   |
   |<---- test_linux.sh <--- vars_custom_linux.sh
   |          |
   |          |__out__ `soc-linux-<os/os version>-(<date>).csv`
   |
   |<---- test_ssh.sh <--- vars_custom_ssh.sh
   |          |
   |          |__out__ `soc-ssh-<os/os version>-(<date>).csv`
   |
   |
   |... more test scripts if available
```

Output (summarized)
```console
[vagrant@localhost ~]$ sudo ./start_testing.sh

-------------------------------------------------------------------------------
 Telekom IT/DevSecOps - Compliance Check for Linux based systems
-------------------------------------------------------------------------------
   Host: localhost.localdomain
   Date: 10.06.2020
   OS: CentOS Linux
   Version: 7 (Core)
-------------------------------------------------------------------------------

[Pre-Check] Check if running Linux version is supported: PASSED
[Pre-Check] Check if script is started with root priviledges: PASSED
[Pre-Check] Write log data to test-log-centos7-(2020-10-06).log: PASSED
[Pre-Check] Load test cases from file : PASSED
[Pre-Check] Write SoC for PSA to soc-linux-centos7-(2020-10-06).csv: PASSED
[Pre-Check] Read variables from file vars_custom_linux.sh: PASSED

===============================================================================
 Compliance Checks - Linux OS for Servers (3.65)
===============================================================================
Start testing ...

++ Req 1: Unused services and protocols must be deactivated.
   [Test 1.01] Check open tcp port 22 (port defined as allowed): PASSED
   [Test 2.01] Check open udp port 68 (user defined allowed port): PASSED
   [Test 2.02] Check open udp port 60228 (needed for rsyslog): PASSED

<<< cut >>>

... Testing finished

[Pre-Check] Load test cases from file test_ssh.sh: PASSED
[Pre-Check] Check if OpenSSH is installed: PASSED
[Pre-Check] Check if SSH deamon is running: PASSED
[Pre-Check] Read variables from file vars_custom_ssh.sh: PASSED

===============================================================================
 Compliance Checks - Linux OS for Servers (3.65)
===============================================================================
Start testing ...

++ Req 1: The SSH protocol version 2 must be used.
   [Test 1.01] Check ssh protocol version: PASSED
	NOTE! SSH software version detected: 7.4.

++ Req 2: SSH moduli smaller than 2048 must not be used.
   [Test 1.01] Check moduli >= 2048: FAILED (found moduli < 2048)

<<< cut >>>

... Testing finished

-------------------------------------------------------------------------------
SUMMARY (CentOS Linux 7)
-------------------------------------------------------------------------------
Test Cases: 533  |  Passed: 453  |  Failed: 69  |  Skipped: 11

```
#### Output Files

In this default configuration the following two output files will be generated:

- `test-log-<os/os version>-(<date>).log` (example: test-log-centos7-(2020-10-06).log)

This log file includes the output of the start script inclusive all test results.

- `soc-<tests>-<os/os version>-(<date>).csv` (example: soc-linux-centos7-(2020-10-06).csv)

This output files are generated for any test script that is executed from start script. It generates a "Statement of Compliance (SoC) list that is needed for "Privacy & Security Assessment" (PSA) process from Telekom Security. 

The format is 'comma separated values'. These files can be imported in Microsoft Excel to generate a table from it. The used delimiter is used to give the border between the different columns.

>NOTE We use the ';' as delimiter as!

Example of SoC file:
```console
[vagrant@localhost ~]$ cat soc-linux-centos7-\(2020-10-06\).csv 
ReqNo.;Requirement;Statement of Compliance
Req 1;Unused services and protocols must be deactivated.;Compliant;
Req 2;The reachability of services must be restricted.;Compliant;
Req 3;Unused software must not be installed or must be uninstalled.;Partly Compliant;Not allowed server(s): avahi
<<< cut >>>
```

### Custom Variables Script

The varaibles file (file: `vars-custom-<name>.sh`) can be used to define an own set of variables for the compliance checks for the used test script. To use the variables file place it must be stored in the same folder as the test script. The name of the variable file (example: vars_custom_ssh.sh) is fix and can not be changed! If it is changed the file will not be used during execution of the test script.

> NOTE  
Default values will be used for all variables, if the corresponding variable file didn't exist in the the same folder as the test script.

The following variables are available:

| Type |    Variable        | Description |
|------|--------------------|-------------|
| 01   | REQnn="`<value>`"; | Variable to enable (TRUE) or disable (FALSE) the testing for a specific requirement. If a requirement is disabled it will be marked with N/A in SoC list generated by the test script. |
| 02   | REMARK_REQnn="";   | Option to define a comment that will be written for the specific requirement to the SoC list generated by the test script. |
| 03   | custom variables   | For some requirements additional variables can be configured with customer specific values. If not changed the default value will be used. |

Example for variables:
```console
# Req-1: Unused services and protocols must be deactivated.
REQ1="TRUE"
REMARK_REQ1=""

        # Define allowed TCP/UDP ports. Example: TCP_PORTS="22 80 443" 
        TCP_PORTS="22"
        UDP_PORTS="68 123"
```

- variable `REQ1`: type 01
- variable `REMARK_REQ1`: type 02
- variable `TCP_PORTS`: type 03

## References

Telekom Security - Security Requirements:

- SecReq 3.65: Linux OS for Servers (version 1.4; 01.07.2020)
- SecReq 3.04: SSH (version 2.7, 01.07.2020)

The document can be found on [Telekom Security PSA Portal](https://psa-portal.telekom.de) (only internal).

A public available complete set of all security requirements of Deutsche Telekom AG can be downloaded here: [Telekom Security - Requirements](https://www.telekom.com/resource/blob/327540/0af4a73d01334926f71d5530a2c2477e/dl-security-requirements-data.zip) (ZIP file)

## License

Apache License, Version 2.0

See file [LICENSE](./LICENSE)
