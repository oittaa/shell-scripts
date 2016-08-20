#!/bin/sh
set -e

[ -f /var/cryptswap ] && {
    echo "/var/cryptswap exists already."
    exit 1
}
[ ! -f /etc/crypttab ] && {
    echo "/etc/crypttab is missing."
    exit 1
}
command -v cryptsetup >/dev/null 2>&1 || {
    echo "Command cryptsetup is missing. Please, install cryptsetup package."
    exit 1
}

fallocate -l 2G /var/cryptswap
grep -q "^cryptswap" /etc/crypttab || echo "cryptswap	/var/cryptswap		/dev/urandom	swap" >> /etc/crypttab
service cryptdisks reload
grep -q "^/dev/mapper/cryptswap" /etc/fstab || echo "/dev/mapper/cryptswap none swap sw 0 0" >> /etc/fstab
swapon -a
