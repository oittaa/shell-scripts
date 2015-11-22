* `entware-setup.sh`
* `opkg install openssh-server`
* `ssh-keygen -t ed25519 -f /opt/etc/ssh/ssh_host_ed25519_key`
* Copy all provided scripts and configuration files to the router. 
```
curl -o /jffs/scripts/shadow.postconf https://raw.githubusercontent.com/oittaa/shell-scripts/master/asuswrt-merlin/jffs/scripts/shadow.postconf && chmod 755 /jffs/scripts/shadow.postconf
curl -o /jffs/scripts/passwd.postconf https://raw.githubusercontent.com/oittaa/shell-scripts/master/asuswrt-merlin/jffs/scripts/passwd.postconf && chmod 755 /jffs/scripts/passwd.postconf
curl -o /opt/etc/init.d/S40sshd https://raw.githubusercontent.com/oittaa/shell-scripts/master/asuswrt-merlin/opt/etc/init.d/S40sshd && chmod 755 /opt/etc/init.d/S40sshd
curl -o /opt/etc/ssh/sshd_config https://raw.githubusercontent.com/oittaa/shell-scripts/master/asuswrt-merlin/opt/etc/ssh/sshd_config && chmod 644 /opt/etc/ssh/sshd_config
```
* Restart the router.
