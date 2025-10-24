#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[1/10] Updating package lists and upgrading..."
sudo apt-get update -y
sudo apt-get upgrade -y

echo "[2/10] Installing base tools (OpenVPN, Screen)..."
sudo apt-get install -y openvpn screen

echo "[3/10] Installing system packages required by browsers/WebDriver..."
sudo apt-get install -y \
  python3 python3-pip unzip curl wget git xvfb ca-certificates apt-transport-https gnupg \
  libxi6 libgconf-2-4 libnss3 libxss1 libatk-bridge2.0-0 \
  libgtk-3-0 libxcb1 libxcomposite1 libxrandr2 libasound2 \
  libpangocairo-1.0-0 libpangoft2-1.0-0 libxdamage1 \
  libx11-xcb1 libxtst6 libxrender1 xdg-utils libpango1.0-0 \
  libdbus-glib-1-2 libgbm-dev libxshmfence1 \
  software-properties-common openssl

echo "[4/10] Installing security/network tools (system-wide)..."
# Needed by your diagnostics:
# - nmap (ports)
# - traceroute (system traceroute)
# - iputils-ping (ping)
if ! dpkg -s nmap >/dev/null 2>&1; then
  sudo apt-get install -y nmap
fi
if ! dpkg -s traceroute >/dev/null 2>&1; then
  sudo apt-get install -y traceroute
fi
if ! dpkg -s iputils-ping >/dev/null 2>&1; then
  sudo apt-get install -y iputils-ping
fi

# testssl.sh (via apt if available; else from upstream)
if apt-cache show testssl.sh >/dev/null 2>&1; then
  sudo apt-get install -y testssl.sh
else
  echo "testssl.sh package not found in apt cache; installing from upstream..."
  sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
  sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
  sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
fi

echo "[5/10] Installing Python packages globally (no requirements.txt)..."
python3 -m pip install --upgrade pip
# Use Selenium Manager (bundled with Selenium >=4.10) — no chromedriver_py
python3 -m pip install \
  "selenium>=4.14,<5" \
  "selenium-wire>=5,<6" \
  "requests>=2,<3" \
  "pandas>=2,<3" \
  "scapy>=2.5,<3" \
  urllib3 certifi idna chardet

# Optional: allow Scapy to send raw packets without sudo by granting CAP_NET_RAW to python3
# This may fail in some environments (snap/readonly FS) — it's fine to proceed if it does.
echo "[6/10] (Optional) Granting CAP_NET_RAW to python3 for Scapy..."
PYBIN="$(command -v python3 || true)"
if [ -n "${PYBIN}" ]; then
  if command -v setcap >/dev/null 2>&1; then
    sudo setcap cap_net_raw+ep "${PYBIN}" || echo "setcap failed (continuing without it)"
    command -v getcap >/dev/null 2>&1 && getcap "${PYBIN}" || true
  else
    echo "setcap not available; skipping capability grant"
  fi
fi

echo "[7/10] Installing Google Chrome Stable via APT..."
# Official Google repo
if ! grep -q "dl.google.com/linux/chrome/deb" /etc/apt/sources.list.d/google-chrome.list 2>/dev/null; then
  wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo gpg --dearmor -o /usr/share/keyrings/google-linux.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux.gpg] http://dl.google.com/linux/chrome/deb/ stable main" | \
    sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  sudo apt-get update -y
fi
sudo apt-get install -y google-chrome-stable

# Remove any stale chromedriver to force Selenium Manager to fetch the correct version
if [ -f /usr/local/bin/chromedriver ]; then
  echo "Removing stale /usr/local/bin/chromedriver to let Selenium Manager pick the right driver..."
  sudo rm -f /usr/local/bin/chromedriver
fi

echo "[8/10] Installing Firefox + Geckodriver (system-wide)..."
if ! command -v firefox >/dev/null 2>&1; then
  if ! sudo apt-get install -y firefox; then
    echo "Apt Firefox not available; installing via snap..."
    sudo snap install firefox
  fi
fi
if ! command -v geckodriver >/dev/null 2>&1; then
  if ! sudo apt-get install -y geckodriver; then
    echo "Installing Geckodriver from GitHub release..."
    GD_VER="v0.34.0"
    wget -q "https://github.com/mozilla/geckodriver/releases/download/${GD_VER}/geckodriver-${GD_VER}-linux64.tar.gz" -O /tmp/geckodriver.tgz
    tar -xzf /tmp/geckodriver.tgz -C /tmp
    sudo mv -f /tmp/geckodriver /usr/local/bin/geckodriver
    sudo chmod +x /usr/local/bin/geckodriver
    rm -f /tmp/geckodriver.tgz
  fi
fi

echo "[9/10] Installing Brave browser (system-wide)..."
if ! command -v brave-browser >/dev/null 2>&1; then
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg \
    | sudo tee /etc/apt/keyrings/brave-browser-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/etc/apt/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" \
    | sudo tee /etc/apt/sources.list.d/brave-browser-release.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y brave-browser
fi
# Normalize Brave binary name if needed
if [ ! -x "/usr/bin/brave-browser" ] && [ -x "/usr/bin/brave-browser-stable" ]; then
  sudo ln -sf /usr/bin/brave-browser-stable /usr/bin/brave-browser
fi

echo "[10/10] Finalizing…"
echo "Selenium Manager will auto-download matching WebDrivers at runtime."
echo "Installed: Chrome/Brave/Firefox, nmap, traceroute, ping, testssl.sh, and Scapy (pip)."
echo "If Scapy traceroute fails without sudo, try running the script as root or ensure CAP_NET_RAW was applied."
