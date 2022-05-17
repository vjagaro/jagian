#!/bin/bash

set -euo pipefail

ROOT_DIR="$(dirname "$(readlink -f -- "$0")")"
TOOLS_BIN_DIR="$ROOT_DIR/bin"
CONFIG_PATH="$ROOT_DIR/config.conf"
LOG_DIR="$ROOT_DIR/logs"
LOG_PATH="$LOG_DIR/$(date +%Y%m%d-%H%M%S).log"

moot() {
  MOOT_SHELL_ENV="$(
    cat <(declare -p | grep -vE '^declare -(r|.r)') <(declare -fp) \
      <(echo "set -eou pipefail")
  )" command moot --log "$LOG_PATH" "$@"
}

if [ "$(id -u)" -ne "0" ]; then
  echo >&2 "ERROR: Must run as root."
  exit 1
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo >&2 "ERROR: $CONFIG_PATH does not exist."
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"

PATH="$TOOLS_BIN_DIR:$PATH"

if [ -n "$APT_CACHER_URL" ]; then
  HTTPS=http://HTTPS/
else
  # shellcheck disable=SC2034
  HTTPS=https:
fi

# Remove old log files
find logs -type f -and -not -name '.gitignore' -and -mtime +1 -exec rm -f {} \;

moot "Configuring proxy" <<'moot'
  perl -pi -e "s/^Acquire::https?::Proxy.*$//g" /etc/apt/apt.conf
  if [ -n "$APT_CACHER_URL" ]; then
    echo "Acquire::http::Proxy \"$APT_CACHER_URL\";" >/etc/apt/apt.conf.d/00proxy
  else
    rm -f /etc/apt/apt.conf.d/00proxy
  fi
moot

moot "Updating system" \
  apt-get update

DEBIAN_FRONTEND=noninteractive \
  moot "Upgrading system" \
  apt-get dist-upgrade -y

moot "Installing desktop" \
  apt-ensure task-gnome-desktop

moot "Configuring desktop" <<'moot'
  perl -pi -e 's/^(#\s*)?(AutomaticLoginEnable\b).*$/\2=true/' \
    /etc/gdm3/daemon.conf
  perl -pi -e "s/^(#\\s*)?(AutomaticLogin\\b).*$/\\2=$LOCAL_USER/" \
    /etc/gdm3/daemon.conf
  perl -pi -e "s/^(#\s*)?(sleep-inactive-ac-timeout\b).*$/\\2=0/" \
    /etc/gdm3/greeter.dconf-defaults
  perl -pi -e "s/^(#\s*)?(sleep-inactive-ac-type\b).*$/\\2='nothing'/" \
    /etc/gdm3/greeter.dconf-defaults
  perl -pi -e "s/^(#\s*)?(sleep-inactive-battery-timeout\b).*$/\\2=0/" \
    /etc/gdm3/greeter.dconf-defaults
  perl -pi -e "s/^(#\s*)?(sleep-inactive-battery-type\b).*$/\\2='nothing'/" \
    /etc/gdm3/greeter.dconf-defaults
moot

moot "Configuring firewall" <<'moot'
  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy accept;

    iifname "lo" accept
    ct state { established, related } counter accept
    ct state invalid counter drop
    ip protocol icmp counter accept
    ip6 nexthdr ipv6-icmp counter accept

    tcp dport ssh counter accept
    # Mosh
    udp dport 60000-61000 counter accept
    # Syncthing
    tcp dport 22000 counter accept
    udp dport 22000 counter accept
    udp dport 21027 counter accept

    counter reject
  }

  chain forward {
    type filter hook forward priority filter; policy accept;
    counter reject
  }

  chain output {
    type filter hook output priority filter; policy accept;
    counter accept
  }
}
EOF

  systemctl enable nftables
  systemctl restart nftables
moot

moot "Configuring hostname" <<'moot'
  echo "$LOCAL_HOSTNAME" >/etc/hostname
  hostname -F /etc/hostname
moot

moot "Configuring /etc/hosts" <<'moot'
  cat <<EOF >/etc/hosts
127.0.0.1	localhost
127.0.1.1	$LOCAL_HOSTNAME
$APT_CACHER_IP	apt-cacher

# The following lines are desirable for IPv6 capable hosts
::1	localhost ip6-localhost ip6-loopback
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
EOF
moot

moot "Configuring wired connection" <<'moot'
  nmcli connection modify 'Wired connection 1' \
    ipv4.method manual \
    ipv4.address "$LOCAL_IPV4_ADDRESS/$LOCAL_IPV4_CIDR" \
    ipv4.gateway "$LOCAL_IPV4_GATEWAY" \
    ipv4.dns "$LOCAL_IPV4_DNS"
  nmcli connection up 'Wired connection 1'
moot

moot "Installing WireGuard" \
  apt-ensure wireguard

moot "Configuring WireGuard" <<'moot'
  touch /etc/wireguard/wg0.conf
  chmod 600 /etc/wireguard/wg0.conf
  cat <<-EOF >/etc/wireguard/wg0.conf
[Interface]
Address = $WG_IPV4, $WG_IPV6
DNS = $VPN_DNS_IPV4, $VPN_DNS_IPV6
PrivateKey = $WG_PRIVATE_KEY

[Peer]
PublicKey = $VPN_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $VPN_ENDPOINT:51820
EOF

  nmcli connection delete wg0 || true
  nmcli connection import type wireguard file /etc/wireguard/wg0.conf

  cat <<EOF >/etc/systemd/system/reconnect-wireguard.service
[Unit]
After=graphical.target
Description=Reconnect wireguard on boot

[Service]
Type=simple
ExecStart=bash -c 'sleep 1 && /usr/bin/nmcli connection up wg0'

[Install]
WantedBy=graphical.target
EOF

  systemctl daemon-reload
  systemctl enable reconnect-wireguard
moot

moot "Installing OpenSSH" \
  apt-ensure openssh-server mosh

moot "Configuring OpenSSH" <<'moot'
  perl -pi -e 's/^#?PasswordAuthentication .*$/PasswordAuthentication no/g' \
    /etc/ssh/sshd_config
  systemctl restart ssh
moot

moot "Configuring Timezone" \
  timedatectl set-timezone America/Los_Angeles

moot "Increasing file watches limit" <<'moot'
  echo "fs.inotify.max_user_watches = 524288" >/etc/sysctl.d/max_user_watches.conf
  sysctl --quiet --system
moot

moot "Installing many programs" \
  apt-ensure python3 python3-dev python3-pip python3-venv \
  apt-transport-https ca-certificates lsb-release \
  curl gpg git htop mtr netcat nmap rsync tcpdump wget zstd \
  iftop iptraf-ng p7zip-full unzip xz-utils zip \
  cryptsetup fd-find fzf jq shellcheck silversearcher-ag tmate \
  adb fastboot remmina \
  gimp jpegoptim optipng poppler-utils \
  audacity ffmpeg sox

ln -sf /usr/bin/fdfind /usr/local/bin/fd

moot "Installing Docker" <<'moot'
  add-apt-external-source -q docker \
    https://download.docker.com/linux/debian/gpg \
    "deb [%] $HTTPS//download.docker.com/linux/debian $(lsb_release -sc) stable"
  apt-ensure docker-ce docker-ce-cli containerd.io
moot

moot "Installing NodeJS" <<'moot'
  add-apt-external-source -q nodejs \
    https://deb.nodesource.com/gpgkey/nodesource.gpg.key \
    "deb [%] $HTTPS//deb.nodesource.com/node_18.x $(lsb_release -sc) main"
  apt-ensure nodejs
moot

moot "Installing Signal Desktop" <<'moot'
  add-apt-external-source -q signal-desktop \
    https://updates.signal.org/desktop/apt/keys.asc \
    "deb [%] $HTTPS//updates.signal.org/desktop/apt xenial main"
  apt-ensure signal-desktop
moot

moot "Installing Syncthing source" <<'moot'
  add-apt-external-source syncthing \
    https://syncthing.net/release-key.gpg \
    "deb [%] $HTTPS//apt.syncthing.net/ syncthing stable"
  apt-ensure syncthing
moot

moot "Installing VS Code source" <<'moot'
  add-apt-external-source -q vscode \
    https://packages.microsoft.com/keys/microsoft.asc \
    "deb [%] $HTTPS//packages.microsoft.com/repos/code stable main"
  apt-ensure code
moot

moot "Installing pipx" <<'moot'
  install-python-package pipx
  ln -sf /opt/python/pipx/bin/pipx /usr/local/bin/pipx
moot

moot "Installing Anki" <<'moot'
  url="$(curl -s "https://api.github.com/repos/ankitects/anki/releases/latest" |
    grep 'linux-qt5.tar.zst"$' | sed 's/^.*"\(.*\)"$/\1/')"
  pkg="/var/cache/download/anki.tar.zst"

  if download-if-modified -qo "$pkg" "$url" || [ ! -x /usr/local/bin/anki ]; then
    tmp="$(mktemp -d)"
    cd "$tmp"
    unzstd -c "$pkg" | tar -x
    cd *
    ./install.sh >/dev/null
    rm -rf "$tmp"
  fi
moot

moot "Installing Firefox" <<'moot'
  apt-ensure libdbus-glib-1-2

  url="https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US"
  pkg="/var/cache/download/firefox.tar.bz2"

  if download-if-modified -qo "$pkg" "$url" || [ ! -x /opt/firefox/firefox ]; then
    cd /opt
    tar jxf "$pkg"
  fi

  cat <<EOF >/usr/share/applications/firefox.desktop
[Desktop Entry]
Name=Firefox
Comment=Web Browser
Exec=/opt/firefox/firefox %u
Terminal=false
Type=Application
Icon=/opt/firefox/browser/chrome/icons/default/default128.png
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;application/vnd.mozilla.xul+xml;application/rss+xml;application/rdf+xml;image/gif;image/jpeg;image/png;x-scheme-handler/http;x-scheme-handler/https;
StartupNotify=true
Actions=Private;
EOF
moot

moot "Removing Firefox ESR" <<'moot'
  apt-installed firefox-esr && apt-get purge -y firefox-esr
  cat >/etc/apt/preferences.d/remove-firefox-esr <<-EOF
Package: firefox-esr
Pin: release *
Pin-Priority: -1
EOF
moot

moot "Installing fonts" <<'moot'
  mkdir -p /usr/share/fonts/truetype/local
  if [ ! -f /usr/share/fonts/truetype/local/source-code-pro.ttf ]; then
    wget -qO /usr/share/fonts/truetype/local/source-code-pro.ttf \
      "https://raw.githubusercontent.com/google/fonts/main/ofl/sourcecodepro/SourceCodePro%5Bwght%5D.ttf"
    fc-cache -f
  fi
moot

moot "Configuring local user password-less sudo" <<'moot'
  echo "$LOCAL_USER ALL=(ALL:ALL) NOPASSWD: ALL" >"/etc/sudoers.d/$LOCAL_USER"
  chmod 440 "/etc/sudoers.d/$LOCAL_USER"
moot

moot "Configuring local user Syncthing" <<'moot'
  systemctl enable "syncthing@$LOCAL_USER"
  systemctl start "syncthing@$LOCAL_USER"
moot

moot "Configuring local user Docker" \
  adduser "$LOCAL_USER" docker

moot "Configuring local user VirtualBox filesharing" \
  adduser "$LOCAL_USER" vboxsf

for pkg in \
  autopep8 \
  black \
  docker-compose \
  linode-cli \
  magic-wormhole \
  poetry \
  youtube-dl; do
  moot "Installing local user pipx $pkg" \
    sudo -u "$LOCAL_USER" -i pipx install "$pkg"
done

moot "Upgrading local user pipx packages" \
  sudo -u "$LOCAL_USER" -i pipx upgrade-all

for ext in \
  esbenp.prettier-vscode \
  foxundermoon.shell-format \
  ms-python.python \
  stkb.rewrap \
  timonwong.shellcheck; do
  moot "Installing local user VS Code $ext" \
    sudo -u "$LOCAL_USER" -i code --force --install-extension "$ext"
done

moot "Configuring local user sleep" <<'moot'
  sudo -u "$LOCAL_USER" -i bash <<EOF
    gsettings set org.gnome.desktop.session idle-delay 0
    gsettings set org.gnome.settings-daemon.plugins.power idle-dim false
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing
EOF
moot

moot "Cleaning up apt" <<'moot'
  apt-get autoremove -y
  apt-get clean
moot
