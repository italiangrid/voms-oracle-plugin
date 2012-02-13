Name:		voms-oracle-plugin
Version:	3.1.15
Release:	1%{?dist}
Summary:	VOMS server plugin for ORACLE

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		https://wiki.italiangrid.it/twiki/bin/view/VOMS
Source:		%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides:	voms-oracle = %{version}-%{release}
Obsoletes:	voms-oracle < %{version}-%{release}
Requires:	voms-server%{?_isa}

BuildRequires:	libtool
BuildRequires:	oracle-instantclient-devel%{?_isa}
BuildRequires:	oracle-instantclient-basic%{?_isa}

%description
The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for
authorization purposes.

This package provides the ORACLE connector for the VOMS server.

%prep
%setup -q
./autogen.sh

%build
%configure  --with-oracle-prefix=%{oracle_prefix} \
            --with-oracle-version=%{oracle_version}

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm $RPM_BUILD_ROOT%{_libdir}/libvomsoracle.a
rm $RPM_BUILD_ROOT%{_libdir}/libvomsoracle.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_datadir}/voms/voms-oracle.data
%{_libdir}/libvomsoracle.so

%changelog
* Tue May 31 2011 Andrea Ceccanti <andrea.ceccanti@cnaf.infn.it> - 3.1.15-1
- First build.
