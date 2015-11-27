#!/bin/sh

# Options: [--patch <ubuntu.img>]

SSHPUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP0AsE3uu/ia2F5jlY8Uq9CcgUjEDp/eKvP/Kn9wAyES"
NETWORKTEST=$(grep '^deb http' /etc/apt/sources.list.d/* /etc/apt/sources.list 2> /dev/null | awk '{ print $2 }' | head -n1)

if [ $(id -u) -ne 0 ]
then
  printf "Script must be run as root. Try 'sudo %s'\n" "$0"
  exit 1
fi

if [ "$1" = "--patch" ]
then
  if [ -z "$2" ] || [ ! -e "$2" ]
  then
    printf "File doesn't exist\n"
    exit 1
  fi
  # Abort, if something goes wrong.
  set -e
  IMG="$2"
  WORKDIR=$(mktemp -d --tmpdir -- "$(basename $0).XXXXXXXXXX")
  LOOPDEV=$(losetup -f)
  SECTORSIZE=$(fdisk -lu "$IMG" 2> /dev/null | grep "^Sector size" | awk '{ print $4 }')
  SECTORCOUNT=$(fdisk -lu "$IMG" 2> /dev/null | tail -n1 | sed 's/.*\s\([0-9]\+\)\s\+[0-9]\+\s\+[0-9]\+\s\+83\s\+Linux$/\1/')
  if ! echo "$SECTORSIZE" | grep -q '^[0-9]\+$' || \
     ! echo "$SECTORCOUNT" | grep -q '^[0-9]\+$'
  then
    printf "Disk %s doesn't contain a valid partition table\n" "$IMG"
    exit 1
  fi
  losetup -o $((${SECTORSIZE}*${SECTORCOUNT})) "$LOOPDEV" "$IMG"
  mount "$LOOPDEV" "$WORKDIR"
  if [ ! -d "${WORKDIR}/usr/lib/raspberrypi/firmware" ] || \
     [ ! -f "${WORKDIR}/etc/dpkg/origins/ubuntu" ] || \
     [ ! -d "${WORKDIR}/usr/local/sbin/" ] || \
     [ ! -f "${WORKDIR}/etc/rc.local" ]
  then
    printf "Disk %s doesn't contain Ubuntu for Raspberry Pi\n" "$IMG"
    exit 1
  fi
  cp "$0" "${WORKDIR}/usr/local/sbin/raspberry-config"
  chown  root:root "${WORKDIR}/usr/local/sbin/raspberry-config"
  chmod 755 "${WORKDIR}/usr/local/sbin/raspberry-config"
  grep -q "^/usr/local/sbin/raspberry-config" "${WORKDIR}/etc/rc.local" || \
    sed -i 's/^\(exit 0\)/\/usr\/local\/sbin\/raspberry-config >> \/var\/log\/raspberry-config.log 2>\&1 \&\n\1/' "${WORKDIR}/etc/rc.local"
  umount "$WORKDIR"
  losetup -d "$LOOPDEV"
  rmdir "$WORKDIR"
  echo "Patched!"
  exit 0
fi

if [ ! -e /boot/config.txt ] || \
   ! dpkg -l | grep -q "^ii\s\+raspberrypi-bootloader"
then
  printf "This script only works on Raspberry Pi. https://wiki.ubuntu.com/ARM/RaspberryPi\n"
  exit 1
fi

APTUPDATED="no"
inst_pkg () {
  COUNTER=0
  LIMIT=1
  while ! wget -q -O /dev/null "${NETWORKTEST}"
  do
    COUNTER=$((${COUNTER}+1))
    if [ $COUNTER -ge $LIMIT ]
    then
      printf "%s waiting for a network connection\n" "$(date +'%Y-%m-%d %T')"
      COUNTER=0
      LIMIT=$((${LIMIT}*2))
    fi
    sleep 1
  done
  if [ "$APTUPDATED" = "no" ]
  then
    apt-get -q update
    APTUPDATED="yes"
  fi
  apt-get -q -y install "${1}"
}

printf "%s STARTING\n" "$(date +'%Y-%m-%d %T')"

### Expand the root filesystem to fill the whole card,
# if there's more than 10MB of free space on the memory card
PART_NUM=2
FREEBYTES=$(parted /dev/mmcblk0 unit B print free | grep 'Free Space' | tail -n1 | awk '{print substr($3, 1, length($3)-1)}')
if [ -n "${FREEBYTES}" ] && \
   [ "${FREEBYTES}" -ge 10485760 ] && \
   [ ! -e /dev/mmcblk0p$((${PART_NUM}+1)) ]
then
  PART_START=$(parted /dev/mmcblk0 -ms unit s p | grep "^${PART_NUM}" | cut -f 2 -d: | sed 's/[^0-9]//g')
  fdisk /dev/mmcblk0 <<EOF
p
d
$PART_NUM
n
p
$PART_NUM
$PART_START

p
w
EOF
  # Resize partition after next boot
  mv /etc/rc.local /etc/rc.local.orig
  cat <<EOF > /etc/rc.local &&
#!/bin/sh -e
resize2fs /dev/mmcblk0p${PART_NUM}
mv /etc/rc.local.orig /etc/rc.local
[ -x /etc/rc.local ] && /etc/rc.local
exit 0
EOF
  chmod +x /etc/rc.local
fi

### Abort, if something goes wrong.
set -e

### ZTE MF823 LTE USB Modem
grep -q "^iface usb0" /etc/network/interfaces || printf "\nallow-hotplug usb0\niface usb0 inet dhcp\n" >> /etc/network/interfaces
if lsusb | grep -q "ZTE WCDMA Technologies MSM"
then
  wget -q --referer "http://192.168.0.1/index.html" -O /dev/null "http://192.168.0.1/goform/goform_set_cmd_process?goformId=CONNECT_NETWORK"
  wget -q --referer "http://192.168.0.1/index.html" -O /dev/null "http://192.168.0.1/goform/goform_set_cmd_process?goformId=SET_CONNECTION_MODE&ConnectionMode=auto_dial"
fi

### Enable camera and disable camera led
grep -q "^start_x" /boot/config.txt || echo "start_x=1" >> /boot/config.txt
grep -q "^disable_camera_led" /boot/config.txt ||  echo "disable_camera_led=1" >> /boot/config.txt
grep -q "^gpu_mem" /boot/config.txt || echo "gpu_mem=128" >> /boot/config.txt
which raspistill > /dev/null || inst_pkg libraspberrypi-bin

### Enable Hardware Random Number Generator
if dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096 2> /dev/null && ! which /usr/sbin/rngd > /dev/null
then
  inst_pkg rng-tools
fi

### Configure SSH Server securely - https://stribika.github.io/2015/01/04/secure-secure-shell.html
# If authorized_keys doesn't exist, create it and add the key
if [ ! -e ~ubuntu/.ssh/authorized_keys ]
then
  mkdir -p -m 700 ~ubuntu/.ssh
  chown ubuntu:ubuntu ~ubuntu/.ssh
  echo ${SSHPUBKEY} >> ~ubuntu/.ssh/authorized_keys
  chown ubuntu:ubuntu ~ubuntu/.ssh/authorized_keys
fi
which sshd > /dev/null || inst_pkg openssh-server
SHASUM=$(cat /etc/ssh/sshd_config /etc/ssh/moduli | sha256sum)
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
[ "$SHASUM" != "$(cat /etc/ssh/sshd_config /etc/ssh/moduli | sha256sum)" ] && service ssh restart

### Tor and hidden SSH service
if ! which tor > /dev/null
then
  inst_pkg tor
  echo "HiddenServiceDir /var/lib/tor/hidden_service_ssh" >> /etc/tor/torrc
  echo "HiddenServicePort 22 127.0.0.1:22" >> /etc/tor/torrc
  service tor reload
fi

### Script completed. Remove it from /etc/rc.local
RCLOCAL="/etc/rc.local"
[ -e /etc/rc.local.orig ] && RCLOCAL="/etc/rc.local.orig"
sed -i '/^\/usr\/local\/sbin\/raspberry-config/d' "${RCLOCAL}"
sync
printf "%s FINISHED\n" "$(date +'%Y-%m-%d %T')"

exit 0
