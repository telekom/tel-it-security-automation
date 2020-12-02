#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2020 Maximilian Hertstein, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Deutsche Telekom IT GmbH (DevSecOps Team)
# Start script for compliance testing for Linux based systems
# Version: 1.1
# Date: 14.07.2020 
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Input varibles during script execution
# -----------------------------------------------------------------------------

helpFunction()
{
   echo -e "\nUsage: $0 [OPTIONS] -t [SCRIPT] -o [FILE]"
   echo -e "Script for compliance testing on Linux based systems"
   echo -e "Example: $0 -n -t <test-script> -o <output-file>"
   echo -e "\t-t   Define script with test cases. Otherwise all found scripts"
   echo -e "\t     in same folder as start script are executed."
   echo -e "\t-o   Define name for output file for log data. (default name is"
   echo -e "\t    'test-log-<os><date>.log'). If file exists it will be overwritten"
   echo -e "\t-d   Use default variables and ignore variable files in folder."
   echo -e "\t-x   Write no output files (log/soc)."
   echo -e "\t-n   No OS check will be performed."
   echo -e "\t-q   Script runs in quite mode."
   echo -e "\t-f   If test cases fail script will end with 0 and not 1 as"
   echo -e "\t     error code.\n"
   exit 1
}

TEST_FILE=
OUTPUT_FILE=
DEF_VARS="FALSE"
NO_OUT="FALSE"
OS_CHECK="TRUE"
QUITE_MODE="FALSE"
ERR_HANDLING="TRUE"

while getopts "t:o:dxnqf" opt 2>/dev/null
do
   case "$opt" in
      t ) TEST_FILE="$OPTARG" ;;
      o ) OUTPUT_FILE="$OPTARG" ;;
      d ) DEF_VARS="TRUE" ;;
      x ) NO_OUT="TRUE" ;;
      n ) OS_CHECK="FALSE" ;;
      q ) QUITE_MODE="TRUE" ;;
      f ) ERR_HANDLING="FALSE" ;;
      ? ) helpFunction ;; 
   esac
done

# -----------------------------------------------------------------------------
# Output File Configuration
# -----------------------------------------------------------------------------
DAY=`date +"%Y-%d-%m"`
OS=$(awk -F\= '/^ID=/ {print $2}' /etc/os-release | tr -d '"')
OS_VERSION=$(awk -F\" '/^VERSION_ID=/ {print $2}' /etc/os-release)

if [ "$NO_OUT" != "TRUE" ]; then
  if [ -z "$OUTPUT_FILE" ]; then
    OUT_FILE="test-log-$OS$OS_VERSION-($DAY).log"
    CNT_FILES=0
    if [ -f "$OUT_FILE" ]; then
      CNT_FILES="$(ls | grep "test-log-$OS$OS_VERSION-($DAY)[1-9].*.log" | grep -o ")[1-9].*.log" | sed 's/)//;s/.log$//' | sort -n -r | head -1)"
      let CNT_FILES++;
      OUT_FILE="test-log-$OS$OS_VERSION-($DAY)$CNT_FILES.log"
    fi
  else
    OUT_FILE="$OUTPUT_FILE"
  fi

  touch $OUT_FILE
  chmod 444 $OUT_FILE 2>/dev/null

  if [ "$QUITE_MODE" == "TRUE" ]; then
    exec > $OUT_FILE 2>&1
  else
    exec > >(tee $OUT_FILE) 2>&1
  fi
else
  if [ "$QUITE_MODE" == "TRUE" ]; then exec > /dev/null 2>&1; fi
fi

# -----------------------------------------------------------------------------
# Set script variables
# -----------------------------------------------------------------------------
CNT_PASSED=0
CNT_ERRORS=0
CNT_SKIP=0
ERR=0
TXT=""
ERR_TXT=""

# Check for directory were script is located.
SCRIPT_PATH=$(readlink -f "$0")
CURRENT_DIR=$(dirname "$SCRIPT_PATH")

# -----------------------------------------------------------------------------
# Pre-Checks
# -----------------------------------------------------------------------------

# Function: Output for Pre-Checks
write_error () {
  # $1 = 0: PASSED
  # $1 = 1: FAILED (results in exit 1)
  # $1 = 2: SKIPPED
  if [ "$1" == "0" ]; then
    echo -e "[Pre-Check] $2:\e[1;32m PASSED\e[0m";
    let CNT_PASSED=$CNT_PASSED+1
  elif [ "$1" == "1" ]; then
    echo -e "[Pre-Check] $2:\e[1;31m FAILED\e[0m ($3)";
    echo "-------------------------------------------------------------------------------"
    echo -e " \e[1;31m All tests skipped! \e[0m"
    let CNT_ERRORS=$CNT_ERRORS+1
    exit 1
  elif [ "$1" == "2" ]; then
    echo -e "[Pre-Check] $2: SKIPPED ($3)";
    let CNT_SKIP=$CNT_SKIP+1
  fi
}

TXT="Check if running Linux version is supported"
if [ -f /etc/os-release ]; then
   # Linux OS IDs from file /etc/os-release:
   #   - Amazon Linux = amzn
   #   - RHEL = rhel
   #   - CentOS = centos
   #   - SLES = sles, opensuse-leap
   #   - Ubuntu = ubuntu
   OS=$(awk -F\= '/^ID=/ {print $2}' /etc/os-release | tr -d '"')
   # Full Linux OS name
   OS_NAME=$(awk -F\" '/^NAME=/ {print $2}' /etc/os-release)
   # Linux version (e.g. Ubuntu 18.04)
   OS_VERSION=$(awk -F\" '/^VERSION_ID=/ {print $2}' /etc/os-release)
   # Major version of Linux (e.g. 18 for Ubuntu 18.04)
   MAJOR_VERSION=$(echo $OS_VERSION | awk -F\. '{print $1}')
   if [ "$OS_CHECK" != "FALSE" ]; then
     if [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
       OS_MAIN_DISTRO="REDHAT";
       PACKAGE="rpm -qa";
       ERR_CODE=0;
     elif [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
       OS_MAIN_DISTRO="DEBIAN";
       PACKAGE="apt list --installed";
       ERR_CODE=0;
     elif [ "$OS" == "sles" ] || [ "$OS" == "opensuse-leap" ]; then
       OS_MAIN_DISTRO="SUSE";
       PACKAGE="rpm -qa";
       ERR_CODE=0;
     else
       ERR_CODE=1;
       OS_NAME=$(awk -F\" '/^VERSION=/ {print $2}' /etc/os-release)
       ERR_TXT="Linux $OS_NAME not supported"
     fi
   else
     ERR_CODE=2;
     ERR_TXT="disabled"
   fi
else
  ERR_CODE=1;
  ERR_TXT="Linux not identified";
fi

echo -e "\n-------------------------------------------------------------------------------"
echo " Telekom IT/DevSecOps - Compliance Check for Linux based systems"
echo "-------------------------------------------------------------------------------"
echo "   Host: "$HOSTNAME
echo "   Date: "$(date +"%d.%m.%Y")
echo "   OS: "$(awk -F\" '/^NAME=/ {print $2}' /etc/os-release)
echo "   Version: "$(awk -F\" '/^VERSION=/ {print $2}' /etc/os-release)
echo -e "-------------------------------------------------------------------------------\n"

write_error $ERR_CODE "$TXT" "$ERR_TXT"

# Check if script is started with root priviledges
TXT="Check if script is started with root priviledges"
if [ "$EUID" -ne 0 ]; then
  ERR_CODE=1;
  ERR_TXT="not root";
else
  ERR_CODE=0;
fi
write_error $ERR_CODE "$TXT" "$ERR_TXT"

# Check if log data should be written to output file
if [ "$NO_OUT" != "TRUE" ]; then
  ERR_CODE=0;
  TXT="Write log data to $OUT_FILE";
else
  ERR_CODE=2;
  TXT="Generate output files (.log, .csv)";
  ERR_TXT="disabled"
fi
write_error $ERR_CODE "$TXT" "$ERR_TXT"

# Check if IPv6 is active on system
TXT="Check if IPv6 is active on system"
if [ "$(cat /proc/net/if_inet6 2>/dev/null | wc -c)" -eq 0  ]; then
  echo -e "[Pre-Check] $TXT:\e[1;32m PASSED\e[0m";
  echo -e "\t\e[33mNOTE!\e[0m IPv6 is disabled on the system."
  IPV6_CHECK="OFF";
else
  echo -e "[Pre-Check] $TXT:\e[1;32m PASSED\e[0m";
  echo -e "\t\e[33mNOTE!\e[0m IPv6 is enabled on the system."
  IPV6_CHECK="ON";
fi

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------

soc_outputfile () {
  if [ "$NO_OUT" != "TRUE" ]; then
    OUT_CSV="soc-$1-$OS$OS_VERSION-($DAY).csv"
    CNT_FILES=0
    if [ -f "$OUT_CSV" ]; then
      CNT_FILES="$(ls | grep "soc-$1-$OS$OS_VERSION-($DAY)[1-9].*.csv" | grep -o ")[1-9].*.csv" | sed 's/)//;s/.csv$//' | sort -n -r | head -1)"
      let CNT_FILES++;
      OUT_CSV="soc-$1-$OS$OS_VERSION-($DAY)$CNT_FILES.csv"
    fi
    touch $OUT_CSV
    chmod 444 $OUT_CSV 2>/dev/null
    exec 3>$OUT_CSV
    echo "ReqNo.;Requirement;Statement of Compliance">&3
    echo -e "[Pre-Check] Write SoC for PSA to $OUT_CSV:\e[1;32m PASSED\e[0m";
    let CNT_PASSED=$CNT_PASSED+1
  fi
}

write_to_soc () {
  
  let CNT_ERRORS=$CNT_ERRORS+$1
  let CNT_PASSED=$CNT_PASSED+$2
  let CNT_SKIP=$CNT_SKIP+$3

  if [ "$NO_OUT" == "TRUE" ]; then return 0; fi
  COMMENT=" ";
  if [ -n "$4" ]; then COMMENT="$4"; fi
  
  REQ_TXT_NEW="$(echo $REQ_TXT | sed 's/\\n / /g')";
  if [ $3 -ne 0 ]; then
    echo "Req $REQ_NR;$REQ_TXT_NEW;Not Applicable;$COMMENT">&3;
  elif [ $1 -eq 0 ]; then
    echo "Req $REQ_NR;$REQ_TXT_NEW;Compliant;">&3;
  else
    if [ $2 -ne 0 ]; then
      echo "Req $REQ_NR;$REQ_TXT_NEW;Partly Compliant;$COMMENT">&3;
    else
      echo "Req $REQ_NR;$REQ_TXT_NEW;Not Compliant;$COMMENT">&3;
    fi
  fi
}

# -----------------------------------------------------------------------------
# Read variables from file (...if exists)
# -----------------------------------------------------------------------------

read_variables () {
  # Use variables file defined in loaded script with test cases if found in same
  # folder as
  INPUT_FILE=$1;
  if [ "$DEF_VARS" == "FALSE" ]; then
    if [ -f "$CURRENT_DIR/$INPUT_FILE" ]; then
      source $CURRENT_DIR/$INPUT_FILE
      TXT="Read variables from file $INPUT_FILE";
      ERR_CODE=0
    else
      TXT="Load default variables because no variable file has been found";
      ERR_CODE=0
    fi
  else
      TXT="Default variables are used because use of variables file is disabled";
      ERR_CODE=0
  fi
  
  write_error $ERR_CODE "$TXT" "$ERR_TXT"
}

# -----------------------------------------------------------------------------
# Start compliance checks
# -----------------------------------------------------------------------------

if [ -z "$TEST_FILE" ]; then
  TEST_FILES="$(ls $CURRENT_DIR/test_*.sh)"
  if [ -z "$TEST_FILES" ]; then
    TXT="Load test cases from file";
    ERR_TXT="No test scripts found"
    write_error 1 "$TXT" "$ERR_TXT"
  else
    # Make sure that linux tests are executed first. 
    if [ -n "$(echo $TEST_FILES | grep test_linux.sh)" ]; then
      TXT="Load test cases from file $CURRENT_DIR/test_linux.sh";
      write_error 0 "$TXT" "$ERR_TXT"   
      source $CURRENT_DIR/test_linux.sh skip
    fi
    for FILE in $TEST_FILES; do
      if [ -z "$(echo $FILE | grep test_linux.sh)" ]; then
        TXT="Load test cases from file $FILE";
        write_error 0 "$TXT" "$ERR_TXT"   
        source $FILE skip
      fi
    done
  fi
else
  if [ -f "$TEST_FILE" ]; then
    TXT="Load test cases from file $TEST_FILE";
    write_error 0 "$TXT" "$ERR_TXT"
    source $TEST_FILE skip
  else
    TXT="Load test cases from file";
    ERR_TXT="No test script $TEST_FILE found"
    write_error 1 "$TXT" "$ERR_TXT"
  fi
fi
  
# -----------------------------------------------------------------------------
# Output result of Test script
# -----------------------------------------------------------------------------

CNT_TOTAL=0
let CNT_TOTAL=$CNT_PASSED+$CNT_ERRORS+$CNT_SKIP
echo -e "-------------------------------------------------------------------------------"
echo "SUMMARY ($OS_NAME $OS_VERSION)"
echo -e "-------------------------------------------------------------------------------"
echo -e "Test Cases: $CNT_TOTAL  |  Passed: \e[1;32m$CNT_PASSED\e[0m  |  Failed: \e[1;31m$CNT_ERRORS\e[0m  |  Skipped:$CNT_SKIP\n"


# -----------------------------------------------------------------------------
# Set error code in case of one or more failed checks
# -----------------------------------------------------------------------------

if [ $ERR -ne 0 ] && [ "$ERR_HANDLING" == "TRUE" ]; then
  exit 1
else
  exit 0
fi
