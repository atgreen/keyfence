Name:           keyfence
Version:        0.4.0
Release:        1%{?dist}
Summary:        Credential containment proxy for AI agents

License:        MIT
URL:            https://github.com/atgreen/keyfence
Source0:        keyfence-%{version}.tar.gz

BuildRequires:  golang >= 1.25
BuildRequires:  systemd-rpm-macros

# The binary is statically linked Go with no dynamic dependencies to find.
%global debug_package %{nil}

%description
KeyFence sits between an AI agent and the services it calls. The agent holds
only short-lived, destination-locked kf_ tokens; the real credentials -- API
keys, Bearer tokens, Basic auth, client certificates, SSH private keys -- stay
inside KeyFence and are swapped in on each request. A token that leaks is
worthless anywhere but the one destination it was issued for.

KeyFence runs as a per-user service: the credential store, the certificate
authority and the tokens belong to one person, as do the agents the tokens are
minted for. It is not enabled on installation. To start it:

    systemctl --user enable --now keyfence.socket keyfence-api.socket

Enabling the sockets rather than the service means systemd holds the ports and
starts KeyFence on the first connection, so an enabled broker with nothing to do
costs nothing at all.

%prep
%autosetup

%build
# Fetches modules, so this build wants network access. A spec destined for
# Fedora proper would vendor them and use the go-rpm-macros instead.
export CGO_ENABLED=0
# -buildvcs=false because a source tarball has no repository to stamp from, and
# Go treats not being able to read one as an error rather than as nothing to do.
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="${KEYFENCE_COMMIT:-unknown}"
go build -buildvcs=false \
  -ldflags "-s -w -X main.version=%{version} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
  -o keyfence ./cmd/keyfence

%install
install -Dpm 0755 keyfence %{buildroot}%{_bindir}/keyfence

install -Dpm 0644 releng/keyfence.service %{buildroot}%{_userunitdir}/keyfence.service
install -Dpm 0644 releng/keyfence.socket %{buildroot}%{_userunitdir}/keyfence.socket
install -Dpm 0644 releng/keyfence-api.socket %{buildroot}%{_userunitdir}/keyfence-api.socket
install -Dpm 0644 releng/keyfence-control.socket %{buildroot}%{_userunitdir}/keyfence-control.socket
install -Dpm 0644 releng/keyfence-ssh.socket %{buildroot}%{_userunitdir}/keyfence-ssh.socket

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/keyfence
%{_userunitdir}/keyfence.service
%{_userunitdir}/keyfence.socket
%{_userunitdir}/keyfence-api.socket
%{_userunitdir}/keyfence-control.socket
%{_userunitdir}/keyfence-ssh.socket

# These run "systemctl --user preset", which applies preset policy rather than
# enabling anything: the catch-all for user units is "disable *", so KeyFence is
# installed switched off. Enabling a credential broker on every machine that
# installs the package would open a token-minting API that nobody asked for --
# and with an empty credential store it could not do anything useful anyway.
%post
%systemd_user_post keyfence.service keyfence.socket keyfence-api.socket keyfence-control.socket keyfence-ssh.socket

%preun
%systemd_user_preun keyfence.service keyfence.socket keyfence-api.socket keyfence-control.socket keyfence-ssh.socket

%postun
%systemd_user_postun_with_restart keyfence.service

%changelog
* Sun Sep 20 2026 Anthony Green <green@moxielogic.com> - 0.4.0-1
- Reissue a per-host certificate before it expires, rather than serving an
  expired one for the life of the process.
- Say, in KeyFence's own name, when a client refuses a certificate KeyFence
  minted, instead of leaving the failure to be reported as the origin's.

* Sat Sep 19 2026 Anthony Green <green@moxielogic.com> - 0.3.0-1
- Find a token inside a dotted, JWT-shaped value and swap the whole value, so a
  client that decodes its own credential can be brokered.

* Fri Sep 18 2026 Anthony Green <green@moxielogic.com> - 0.2.0-1
- Add named credentials, keyring integration, token delegation, recent audit
  history, Unix control sockets, passthrough rules, and WebSocket proxying.
- Add standard CLI help and version reporting with release build metadata.
- Harden credential files, control API defaults, SSH host authentication,
  request body limits, token cleanup, and audit records.

* Fri Sep 18 2026 Anthony Green <green@moxielogic.com> - 0.1.0-1
- First package. Ships a per-user service and socket units, installed disabled.
- Listeners default to loopback, and the control API refuses to run without a
  key unless --insecure-api says to.
