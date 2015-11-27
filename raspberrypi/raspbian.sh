#!/bin/sh

SSHPUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP0AsE3uu/ia2F5jlY8Uq9CcgUjEDp/eKvP/Kn9wAyES"
NETWORKTEST=$(grep '^deb http' /etc/apt/sources.list.d/* /etc/apt/sources.list 2> /dev/null | awk '{ print $2 }' | head -n1)

inst_pkg () {
  while ! curl -s "${NETWORKTEST}" > /dev/null
  do
    echo "waiting for a network connection ..."
    sleep 1
  done
  DATE1=$(stat -c %y /var/cache/apt/pkgcache.bin | cut -d' ' -f1)
  DATE2=$(date +"%Y-%m-%d")
  [ "${DATE1}" = "${DATE2}" ] || apt-get -q update
  apt-get -q -y install "${1}"
}

if ! which raspi-config > /dev/null
then
  printf "raspi-config doesn't exist. This script only works on Raspbian. https://www.raspbian.org/\n"
  exit 1
fi

if [ $(id -u) -ne 0 ]
then
  printf "Script must be run as root. Try 'sudo %s'\n" "$0"
  exit 1
fi

### ZTE MF823 LTE USB Modem
if lsusb | grep -q "ZTE WCDMA Technologies MSM" && \
   ip addr | grep -qF "inet 192.168.0."
then
  curl -s --header "Referer: http://192.168.0.1/index.html" "http://192.168.0.1/goform/goform_set_cmd_process?goformId=CONNECT_NETWORK" > /dev/null
  curl -s --header "Referer: http://192.168.0.1/index.html" "http://192.168.0.1/goform/goform_set_cmd_process?goformId=SET_CONNECTION_MODE&ConnectionMode=auto_dial" > /dev/null
fi

### Enable Hardware Random Number Generator
if modprobe -q bcm2708-rng && dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096 2> /dev/null
then
  grep -q "^bcm2708-rng" /etc/modules || echo "bcm2708-rng" >> /etc/modules
  if [ ! -e /etc/default/rng-tools ]
  then
    inst_pkg rng-tools
  fi
fi

### Configure SSH Server securely - https://stribika.github.io/2015/01/04/secure-secure-shell.html
# If authorized_keys doesn't exist, create it and add the key
if [ ! -e ~pi/.ssh/authorized_keys ]
then
  mkdir -p -m 700 ~pi/.ssh
  chown pi:pi ~pi/.ssh
  echo ${SSHPUBKEY} >> ~pi/.ssh/authorized_keys
  chown pi:pi ~pi/.ssh/authorized_keys
fi
# Regenerate keys, because now we should have enough entropy
if [ -e /var/log/regen_ssh_keys.log ]
then
  while [ -e /var/log/regen_ssh_keys.log ] && \
        ! grep -q "^finished" /var/log/regen_ssh_keys.log
  do
    echo "regenerate_ssh_host_keys is still running ..."
    sleep 1
  done
  yes | ssh-keygen -q -N '' -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
  yes | ssh-keygen -q -N '' -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
  rm -f /var/log/regen_ssh_keys.log
fi
# Kex, Ciphers, and MACs
grep -q "^KexAlgorithms " /etc/ssh/sshd_config || echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
grep -q "^Ciphers " /etc/ssh/sshd_config || echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
grep -q "^MACs " /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com" >> /etc/ssh/sshd_config
# Disable DSA and ECDSA host keys
sed -i 's/^\(HostKey \/etc\/ssh\/ssh_host_\(ec\)\?dsa_key\)$/#\1/' /etc/ssh/sshd_config
# Disable password authentication
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# Use primes greater than 2000 bits in moduli file
if [ -e /etc/ssh/moduli ] && \
   awk '$5 <= 2000' /etc/ssh/moduli | grep -q " 2 " && \
   awk '$5 > 2000' /etc/ssh/moduli | grep -q " 2 "
then
  awk '$5 > 2000' /etc/ssh/moduli > "${HOME}/moduli"
  mv "${HOME}/moduli" /etc/ssh/moduli
fi
systemctl restart ssh

### Tor and hidden SSH service
if [ ! -e /etc/tor/torrc ]
then
  inst_pkg tor && \
  echo "HiddenServiceDir /var/lib/tor/hidden_service_ssh" >> /etc/tor/torrc && \
  echo "HiddenServicePort 22 127.0.0.1:22" >> /etc/tor/torrc && \
  systemctl reload tor
fi

### Enable camera and disable camera led
raspi-config nonint do_camera 1
if grep -q "^disable_camera_led=" /boot/config.txt
then
  sed -i "s/^disable_camera_led=.*/disable_camera_led=1/" /boot/config.txt
else
  echo "disable_camera_led=1" >> /boot/config.txt
fi

### Expand the root filesystem to fill the whole card,
# if there's more than 10MB of free space on the memory card
FREEBYTES=$(parted /dev/mmcblk0 unit B print free | grep 'Free Space' | tail -n1 | awk '{print substr($3, 1, length($3)-1)}')
if [ -n "${FREEBYTES}" ] && [ "${FREEBYTES}" -ge 10485760 ]
then
  raspi-config nonint do_expand_rootfs
fi

### Print hidden SSH service address, if it was successfully enabled
if [ -d /var/lib/tor/hidden_service_ssh ]
then
  while [ ! -e /var/lib/tor/hidden_service_ssh/hostname ]
  do
    echo "waiting for Tor hidden service ..."
    sleep 1
  done
  cat /var/lib/tor/hidden_service_ssh/hostname
fi
