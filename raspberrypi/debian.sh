#!/bin/sh

# Options: [--patch <debian.img>]

SSHPUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP0AsE3uu/ia2F5jlY8Uq9CcgUjEDp/eKvP/Kn9wAyES"
NETWORKTEST=$(grep '^deb http' /etc/apt/sources.list.d/* /etc/apt/sources.list 2> /dev/null | awk '{ print $2 }' | head -n1)

### DEBUG
#set -x

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
  if [ ! -f "${WORKDIR}/var/lib/dpkg/info/raspberrypi-bootloader-nokernel.md5sums" ] || \
     [ ! -f "${WORKDIR}/etc/dpkg/origins/debian" ] || \
     [ ! -d "${WORKDIR}/usr/local/sbin/" ] || \
     [ ! -f "${WORKDIR}/etc/rc.local" ]
  then
    printf "Disk %s doesn't contain Debian for Raspberry Pi\n" "$IMG"
    umount "$WORKDIR"
    losetup -d "$LOOPDEV"
    rmdir "$WORKDIR"
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

if ! dpkg -l | grep -q "^ii\s\+raspberrypi-bootloader"
then
  printf "This script only works on Raspberry Pi.\nhttps://wiki.debian.org/RaspberryPi2\nhttps://wiki.ubuntu.com/ARM/RaspberryPi\n"
  exit 1
fi

if [ -f /boot/config.txt ]
then
  CONFIGTXT="/boot/config.txt"
elif [ -f /boot/firmware/config.txt ]
then
  CONFIGTXT="/boot/firmware/config.txt"
else
  printf "Couldn't find /boot/config.txt\n"
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
  if [ "$1" = "-d" ]
  then
    apt-get -q -d -y install "${2}"
  else
    apt-get -q -y install "${1}"
  fi
}

restart_service () {
  if which systemctl > /dev/null
  then
    systemctl restart $1
  elif which service > /dev/null
  then
    service $1 restart
  else
    /etc/init.d/$1 restart
  fi
}

printf "%s STARTING\n" "$(date +'%Y-%m-%d %T')"

# Debian Raspberry image has dangerous [trusted=yes] set for apt sources.
sed -i "s/ \[trusted=yes\] / /" /etc/apt/sources.list

### ZTE MF823 LTE USB Modem
grep -q "^iface usb0" /etc/network/interfaces || printf "\nallow-hotplug usb0\niface usb0 inet dhcp\n" >> /etc/network/interfaces
if grep -q "ZTE.*Technologies MSM" /sys/bus/usb/devices/*/product
then
  wget -q --referer "http://192.168.0.1/index.html" -O /dev/null "http://192.168.0.1/goform/goform_set_cmd_process?goformId=CONNECT_NETWORK"
  wget -q --referer "http://192.168.0.1/index.html" -O /dev/null "http://192.168.0.1/goform/goform_set_cmd_process?goformId=SET_CONNECTION_MODE&ConnectionMode=auto_dial"
fi

### Expand the root filesystem to fill the whole card,
# if there's more than 10MB of free space on the memory card
which parted > /dev/null || inst_pkg parted
PART_NUM=2
FREEBYTES=$(parted /dev/mmcblk0 unit B print free | grep 'Free Space' | tail -n1 | awk '{print substr($3, 1, length($3)-1)}')
if echo "${FREEBYTES}" | grep -q '^[0-9]\+$' && \
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
  # Resize file system after next boot
  mv /etc/rc.local /etc/rc.local.orig
  cat <<EOF > /etc/rc.local &&
#!/bin/sh -e
resize2fs /dev/mmcblk0p${PART_NUM}
mv /etc/rc.local.orig /etc/rc.local
[ "\$(free | grep ^Swap | awk '{ print \$2 }')" = "0" ] && apt-get -q -y install dphys-swapfile
[ -x /etc/rc.local ] && /etc/rc.local
exit 0
EOF
  chmod +x /etc/rc.local
  inst_pkg -d dphys-swapfile
fi

### Abort, if something goes wrong.
set -e

### Enable camera and disable camera led
grep -q "^start_x" "$CONFIGTXT" || echo "start_x=1" >> "$CONFIGTXT"
grep -q "^disable_camera_led" "$CONFIGTXT" ||  echo "disable_camera_led=1" >> "$CONFIGTXT"
grep -q "^gpu_mem" "$CONFIGTXT" || echo "gpu_mem=128" >> "$CONFIGTXT"
which raspistill > /dev/null || inst_pkg libraspberrypi-bin

### Enable Hardware Random Number Generator
! lsmod | grep -q ^bcm2708_rng && modprobe -q bcm2708-rng && \
  ! grep -q "^bcm2708-rng" /etc/modules && echo "bcm2708-rng" >> /etc/modules
if dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096 2> /dev/null
then
  which rngd > /dev/null || inst_pkg rng-tools
fi

### Configure SSH Server securely - https://stribika.github.io/2015/01/04/secure-secure-shell.html
# If authorized_keys doesn't exist, create it and add the key
SSHUSER=root
# "root" for Debian, "ubuntu" for Ubuntu
getent passwd ubuntu > /dev/null && SSHUSER=ubuntu
DIR=$(eval echo "~$SSHUSER")
if [ ! -e "${DIR}/.ssh/authorized_keys" ]
then
  mkdir -p -m 700 "${DIR}/.ssh"
  chown ${SSHUSER}:${SSHUSER} "${DIR}/.ssh"
  echo ${SSHPUBKEY} >> "${DIR}/.ssh/authorized_keys"
  chown ${SSHUSER}:${SSHUSER} "${DIR}/.ssh/authorized_keys"
fi
which sshd > /dev/null || inst_pkg openssh-server
# WARNING! Raspberry image for Debian ships with default SSH host keys!
if [ -f /etc/ssh/ssh_host_ed25519_key ] && [ "$(sha256sum /etc/ssh/ssh_host_ed25519_key | awk '{ print $1 }')" = "1be58e9660ebdf4043822a5322a96273b01c9c6d913114506c19d931cef13bf0" ]
then
  rm /etc/ssh/ssh_host_*
  ssh-keygen -q -N '' -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
  ssh-keygen -q -N '' -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
fi
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
[ "$SHASUM" != "$(cat /etc/ssh/sshd_config /etc/ssh/moduli | sha256sum)" ] && restart_service ssh

### Tor and hidden SSH service
if ! which tor > /dev/null
then
  inst_pkg tor
  echo "HiddenServiceDir /var/lib/tor/hidden_service_ssh" >> /etc/tor/torrc
  echo "HiddenServicePort 22 127.0.0.1:22" >> /etc/tor/torrc
  restart_service tor
fi

### Script completed. Remove it from /etc/rc.local
RCLOCAL="/etc/rc.local"
[ -e /etc/rc.local.orig ] && RCLOCAL="/etc/rc.local.orig"
sed -i '/^\/usr\/local\/sbin\/raspberry-config/d' "${RCLOCAL}"
sync
printf "%s FINISHED\n" "$(date +'%Y-%m-%d %T')"

exit 0
