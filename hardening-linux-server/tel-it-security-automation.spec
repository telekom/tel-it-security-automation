# Macros for py2/py3 compatibility
%if 0%{?fedora} || 0%{?rhel} > 7
%global pyver %{python3_pkgversion}
%else
%global pyver 2
%endif
%global srcname  tel-it-security-automation
%global rolename tel-it-security-automation
%define build_tar_ball 1

Name:           %{rolename}
Version:        1.0+git.1581325755.cffbd5d
Release:        0%{?dist}
Summary:        Ansible playbooks for Security & Compliance Automation from Deutsche Telekom

%if 0%{?suse_version}
Group:          System/Base
%else
Group:          System Environment/Base
%endif
License:        MIT
URL:            https://github.com/telekom/tel-it-security-automation
Source0:        %{name}-%version.tar.xz
BuildArch:      noarch
BuildRequires:  git

# Handle python2 exception
%if %{pyver} == 2
Requires:       ansible
%else
Requires:       python3dist(ansible)
%endif


%description
Ansible playbooks to run Security & Compliance Automation from Deutsche Telekom
IT to harden Linux servers and SSH to the security requirements from DT Security.

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}%{_datadir}/ansible/roles/
mkdir -p %{buildroot}%{_datadir}/ansible/%{name}/
mkdir -p %{buildroot}%{_datadir}/ansible/%{name}/playbooks
mkdir -p %{buildroot}%{_datadir}/ansible/%{name}/playbooks/hardening-linux-server
mkdir -p %{buildroot}%{_datadir}/ansible/%{name}/playbooks/hardening-ssh
mkdir -p %{buildroot}%{_datadir}/doc/%{name}/

cp -rp hardening-linux-server %{buildroot}%{_datadir}/ansible/roles/
cp -rp hardening-ssh %{buildroot}%{_datadir}/ansible/roles/
cp LICENSE %{buildroot}%{_datadir}/ansible/%{name}/
cp LICENSING %{buildroot}%{_datadir}/ansible/%{name}/
cp README* %{buildroot}%{_datadir}/doc/%{name}/
cp -rp images %{buildroot}%{_datadir}/doc/%{name}/

mv %{buildroot}%{_datadir}/ansible/roles/hardening-linux-server/playbook.yml %{buildroot}%{_datadir}/ansible/%{name}/playbooks/hardening-linux-server/
mv %{buildroot}%{_datadir}/ansible/roles/hardening-ssh/playbook.yml %{buildroot}%{_datadir}/ansible/%{name}/playbooks/hardening-ssh/
mv %{buildroot}%{_datadir}/ansible/roles/hardening-*/TelekomSecurity_SecReq*.txt %{buildroot}%{_datadir}/doc/%{name}/

%files
%defattr(-,root,root,-)
%dir %{_datadir}/ansible
%dir %{_datadir}/ansible/%{name}
%{_datadir}/ansible/%{name}/LICENSE
%{_datadir}/ansible/%{name}/LICENSING

# ----------------------------------------------------------------------------------
# tel-it-security-automation playbooks subpackage
# ----------------------------------------------------------------------------------
%package playbooks
Summary:       Ansible playbooks for Security & Compliance Automation from Deutsche Telekom
Requires:      %{name} = %{version}-%{release}
Requires:      %{name}-roles = %{version}-%{release}
BuildArch:     noarch

%description playbooks
Ansible playbooks required for Security & Compliance Automation from Deutsche Telekom
IT to harden Linux servers and SSH to the security requirements from DT Security.

%files playbooks
%defattr(-,root,root,-)
%dir %{_datadir}/ansible/%{name}/playbooks/
%dir %{_datadir}/ansible/%{name}/playbooks/hardening-linux-server
%dir %{_datadir}/ansible/%{name}/playbooks/hardening-ssh
%{_datadir}/ansible/%{name}/playbooks/hardening-linux-server/playbook.yml
%{_datadir}/ansible/%{name}/playbooks/hardening-ssh/playbook.yml

%package roles
# ----------------------------------------------------------------------------------
# tel-it-security-automation roles subpackage
# ----------------------------------------------------------------------------------
Summary:       Ansible roles for Security & Compliance Automation from Deutsche Telekom
Requires:      %{name} = %{version}-%{release}
BuildArch:     noarch

%description roles
Ansible roles required for Security & Compliance Automation from Deutsche Telekom
IT to harden Linux servers and SSH to the security requirements from DT Security.

%files roles
%defattr(-,root,root,-)
%dir %{_datadir}/ansible/roles
%dir %{_datadir}/ansible/roles/hardening-linux-server
%dir %{_datadir}/ansible/roles/hardening-ssh
%{_datadir}/ansible/roles/hardening-linux-server
%{_datadir}/ansible/roles/hardening-ssh
%attr(755, root, root) %{_datadir}/ansible/roles/hardening-linux-server/testing/check_linux.sh
%attr(755, root, root) %{_datadir}/ansible/roles/hardening-ssh/testing/check_ssh.sh

%package docs
# ----------------------------------------------------------------------------------
# tel-it-security-automation docs subpackage
# ----------------------------------------------------------------------------------
Summary:       Documentation for Security & Compliance Automation from Deutsche Telekom
Requires:      %{name} = %{version}-%{release}
BuildArch:     noarch

%description docs
Documentation for Security & Compliance Ansible Automation from Deutsche Telekom
IT to harden Linux servers and SSH to the security requirements from DT Security.

%files docs
%defattr(-,root,root,-)
%dir %{_datadir}/doc/%{name}
%dir %{_datadir}/doc/%{name}/images
%{_datadir}/doc/%{name}/README*
%{_datadir}/doc/%{name}/images/*
%{_datadir}/doc/%{name}/TelekomSecurity_SecReq*.txt

%changelog

