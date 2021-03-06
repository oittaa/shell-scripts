#!/bin/sh

#    Copyright 2019 Eero Vuojolahti <eero@vuojolahti.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This script installs everything needed for a basic filtering mail server.
#
# You might want to edit /etc/exim4/exim4.conf.localmacros afterwards
# and run 'dpkg-reconfigure exim4-config' to configure exim4.
#
# Tested with Debian 9.0 (Stretch) and Ubuntu 18.04 (Bionic Beaver).

######################################################################

# By default accept and relay mail for every domain that has this server's
# address in a MX record.
DEFAULT_LOCAL_DOMAINS="@mx_primary/ignore=127.0.0.1"
DEFAULT_RELAY_DOMAINS="@mx_secondary/ignore=127.0.0.1"

# The following packages will be installed
PKG_LIST="clamav-daemon exim4-daemon-heavy spamassassin razor pyzor greylistd \
    sa-compile libmail-dkim-perl libclamunrar7 unattended-upgrades bind9 wget"

export LC_ALL=C
export LANG=C
export DEBIAN_FRONTEND=noninteractive

usage() {
    cat <<- EOF
	Usage: $0 [OPTION]...
	
	Options:
	  -f, --force
	  -h, --help
	  -l, --local-domains=DOMAIN_LIST
	  -r, --relay-domains=DOMAIN_LIST
	EOF
    exit 1
}

show_help() {
    cat <<- EOF
	Usage: $0 [OPTION]...
	This script installs everything needed for a basic filtering mail server.
	
	Examples:
	  $0 -l 'a.example.org'
	        Accept mail to domain a.example.org and relay to default domains.
	  $0 -l 'a.example.org' -r ''
	        Accept mail to domain a.example.org, but don't relay anywhere.
	  $0 -l '' -r 'a.example.org'
	        Don't treat any domain as local, but relay to a.example.org.
	  $0 -l 'a.example.org;b.example.org' -r 'c.example.org'
	        Accept mail to domains a.example.org and b.example.org, while
	        relaying to c.example.org.
	
	Options:
	  -f, --force
	        Forces default configuration settings to all mail
	        server components provided by this script. Existing
	        packages (exim4-daemon-heavy clamav-daemon spamassassin
	        unattended-upgrades) are only configured with this option.
	  -h, --help
	        Shows this help.
	  -l, --local-domains=DOMAIN_LIST
	        A semicolon-separated list of recipient domains for which this
	        machine should consider itself the final destination. By default
	        all local domains will be treated identically. If both a.example
	        and b.example are local domains, acc@a.example and acc@b.example
	        will be delivered to the same final destination. If different
	        domain names should be treated differently, it is necessary
	        to edit the config files afterwards. This option only affects
	        new installations without exim4-daemon-heavy package or old
	        installations with the force option.
	        Default: $DEFAULT_LOCAL_DOMAINS
	  -r, --relay-domains=DOMAIN_LIST
	        A semicolon-separated list of recipient domains for which this
	        system will relay mail, for example as a fallback MX or mail
	        gateway. This option only affects new installations without
	        exim4-daemon-heavy package or old installations with the force
	        option.
	        Default: $DEFAULT_RELAY_DOMAINS
	
	You can find more information about the special
	patterns starting with '@mx_' from the following link:
	http://www.exim.org/exim-html-current/doc/html/spec_html/ch-domain_host_address_and_local_part_lists.html#SECTdomainlist
	EOF
    exit 0
}

restart_service() {
    if command -v systemctl > /dev/null 2>&1
    then
        systemctl restart $1
    else
        /etc/init.d/$1 restart
    fi
}

# Set internal variables
FORCE=0
LOCAL_DOMAINS="$DEFAULT_LOCAL_DOMAINS"
RELAY_DOMAINS="$DEFAULT_RELAY_DOMAINS"
INITIALIZE_CLAMAV_CONFIG=0
INITIALIZE_EXIM_CONFIG=0
INITIALIZE_SPAM_CONFIG=0
INITIALIZE_APT_CONFIG=0
PKG_INSTALLED=""
PKG_NEEDED=""

# read the options
TEMP=$(getopt -o fhl:r: --long force,help,local-domains:,relay-domains: --name "$0" -- "$@")
[ "$?" != "0" ] && usage
eval set -- "$TEMP"

# extract options and their arguments into variables.
while true
do
    case "$1" in
        -f|--force) FORCE=1 ; shift;;
        -h|--help) show_help ; shift;;
        -l|--local-domains) LOCAL_DOMAINS=$2 ; shift 2 ;;
        -r|--relay-domains) RELAY_DOMAINS=$2 ; shift 2 ;;
        --) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

if [ "$(id -u)" != "0" ]
then
    echo "You must be the superuser to run this script."
    exit 1
fi

for PKG_CUR in $PKG_LIST
do
    if dpkg-query -Wf'${db:Status-abbrev}' "$PKG_CUR" 2>/dev/null | grep -q '^i'
    then
        PKG_INSTALLED="$PKG_INSTALLED $PKG_CUR"
    else
        PKG_NEEDED="$PKG_NEEDED $PKG_CUR"
        case $PKG_CUR in
            libclamunrar7)
                # Package libclamunrar7 requires non-free repositories in Debian.
                lsb_release -i | grep -q 'Debian$' && \
                    sed -i '/non-free/!s/^\(deb[^#]*\)/\1 non-free/' /etc/apt/sources.list ;;
           clamav-daemon)
                INITIALIZE_CLAMAV_CONFIG=1 ;;
            exim4-daemon-heavy)
                INITIALIZE_EXIM_CONFIG=1 ;;
            spamassassin)
                INITIALIZE_SPAM_CONFIG=1 ;;
            unattended-upgrades)
                INITIALIZE_APT_CONFIG=1 ;;
            bind9)
                INITIALIZE_BIND_CONFIG=1 ;;
            *)
                ;;
        esac
    fi
done

if [ "$PKG_NEEDED" != "" ]
then
    [ "$PKG_INSTALLED" != "" ] && \
        printf "Necessary packages already installed:%s\n" "$PKG_INSTALLED"
    printf "Installing following new packages:%s\n" "$PKG_NEEDED"
    apt -q update
    apt -q -y install $PKG_NEEDED
    if [ "$?" != "0" ]
    then
        echo "Something went wrong. Aborting!"
        exit 1
    fi
else
    echo "All necessary packages installed!"
fi

if [ "1" = "$INITIALIZE_SPAM_CONFIG" ] || [ "1" = "$FORCE" ]
then
    echo "### Configuring SpamAssassin ###"

    # Enable SpamAssassin and setup Hash-Sharing Systems
    sed -i -e 's/^ENABLED=0/ENABLED=1/' -e 's/^CRON=0/CRON=1/' /etc/default/spamassassin
    # If you're using systemd (default), the ENABLED setting above isn't used.
    if command -v systemctl > /dev/null 2>&1
    then
        systemctl enable spamassassin.service
    fi
    su -s /bin/sh -c "cd; razor-admin -create; razor-admin -discover" Debian-exim

    # Generate a custom report in the standard X-Spam-Status format and use it
    # later to set a header in Exim. (add_header = X-Spam-Status: $spam_report)
    if [ ! -d /var/spool/exim4/.spamassassin ]
    then
        mkdir -m 700 -p /var/spool/exim4/.spamassassin
        touch /var/spool/exim4/.spamassassin/user_prefs
        chmod 644 /var/spool/exim4/.spamassassin/user_prefs
        chown Debian-exim:Debian-exim /var/spool/exim4/.spamassassin /var/spool/exim4/.spamassassin/user_prefs
    fi
    if ! grep -q '^report' /var/spool/exim4/.spamassassin/user_prefs
    then
        echo 'clear_report_template' >> /var/spool/exim4/.spamassassin/user_prefs
        echo 'report "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"' >> /var/spool/exim4/.spamassassin/user_prefs
    fi

    if [ ! -f /etc/cron.hourly/spamassassin-phishing ]
    then
        cat > /etc/cron.hourly/spamassassin-phishing <<- "EOF"
		#!/bin/sh
		
		PHISHTANK_API_KEY=""
		
		set -e
		
		if [ ! -e /var/lib/spamassassin/phishing ]
		then
		    mkdir -p /var/lib/spamassassin/phishing
		    chown debian-spamd:debian-spamd /var/lib/spamassassin/phishing
		fi
		cd /var/lib/spamassassin/phishing
		
		if [ -n "$PHISHTANK_API_KEY" ]
		then
		    PHISHTANK_URL="https://data.phishtank.com/data/${PHISHTANK_API_KEY}/online-valid.csv"
		else
		    PHISHTANK_URL="https://data.phishtank.com/data/online-valid.csv"
		fi
		
		su -c "wget -N -q 'https://openphish.com/feed.txt'" debian-spamd
		su -c "wget -N -q '$PHISHTANK_URL'" debian-spamd
		EOF
        chown root:root /etc/cron.hourly/spamassassin-phishing
        chmod 755 /etc/cron.hourly/spamassassin-phishing
        /etc/cron.hourly/spamassassin-phishing
    fi

    # Enable HashBL and Phishing plugins
    if ! grep -q '^loadplugin Mail::SpamAssassin::Plugin::HashBL' /etc/spamassassin/v342.pre
    then
        sed -i 's/^# loadplugin Mail::SpamAssassin::Plugin::HashBL$/loadplugin Mail::SpamAssassin::Plugin::HashBL\nheader   HASHBL_EMAIL       eval:check_hashbl_emails('\''ebl.msbl.org'\'')\ndescribe HASHBL_EMAIL       Message contains email address found on EBL/' /etc/spamassassin/v342.pre
    fi
    if ! grep -q '^loadplugin Mail::SpamAssassin::Plugin::Phishing' /etc/spamassassin/v342.pre
    then
        sed -i 's/^# loadplugin Mail::SpamAssassin::Plugin::Phishing$/loadplugin Mail::SpamAssassin::Plugin::Phishing\nifplugin Mail::SpamAssassin::Plugin::Phishing\n  phishing_openphish_feed \/var\/lib\/spamassassin\/phishing\/feed.txt\n  phishing_phishtank_feed \/var\/lib\/spamassassin\/phishing\/online-valid.csv\n  body     URI_PHISHING      eval:check_phishing()\n  describe URI_PHISHING      Url match phishing in feed\nendif/' /etc/spamassassin/v342.pre
    fi
fi

if [ "1" = "$INITIALIZE_CLAMAV_CONFIG" ] || [ "1" = "$FORCE" ]
then
    echo "### Configuring ClamAV ###"

    # UGLY WORKAROUND
    # ClamAV daemon doesn't start automatically in Debian 9 and Ubuntu 18.04
    # right after installation, because the virus database files are missing.
    if command -v systemctl > /dev/null 2>&1 && [ ! -e /etc/systemd/system/clamav-daemon.path ]
    then
        cat > /etc/systemd/system/clamav-daemon.path <<- "EOF"
	[Unit]
	Description=Path Activation for Clam AntiVirus userspace daemon
	Documentation=man:clamd(8) man:clamd.conf(5) http://www.clamav.net/lang/en/doc/

	[Path]
	# Check and wait for database existence before starting up
	PathExistsGlob=/var/lib/clamav/main.{c[vl]d,inc}
	PathExistsGlob=/var/lib/clamav/daily.{c[vl]d,inc}
	EOF
        systemctl start clamav-daemon.path
        rm /etc/systemd/system/clamav-daemon.path
    fi
    # Add ClamAV to Debian-exim group
    groups clamav | grep -q Debian-exim || adduser clamav Debian-exim
    sed -i 's/^AllowSupplementaryGroups false/AllowSupplementaryGroups true/' /etc/clamav/clamd.conf
fi

# Configure Exim to listen on all interfaces, and set relay and recipient domains.
if [ "1" = "$INITIALIZE_EXIM_CONFIG" ] || [ "1" = "$FORCE" ]
then
    echo "### Configuring Exim ###"

    sed -i "\#^dc_eximconfig_configtype=#s#'.*'#'internet'#" /etc/exim4/update-exim4.conf.conf
    sed -i "\#^dc_local_interfaces=#s#'.*'#''#" /etc/exim4/update-exim4.conf.conf
    sed -i "\#^dc_relay_domains=#s#'.*'#'$RELAY_DOMAINS'#" /etc/exim4/update-exim4.conf.conf
    sed -i "\#^dc_other_hostnames=#s#'.*'#'$LOCAL_DOMAINS'#" /etc/exim4/update-exim4.conf.conf

    sed -i "s/^QUEUEINTERVAL='30m'/QUEUEINTERVAL='5m'/" /etc/default/exim4
    sed -i "s/^\trotate 10$/\trotate 30/" /etc/logrotate.d/exim4-base
fi

# Enable automatic upgrades
if [ "1" = "$INITIALIZE_APT_CONFIG" ] || [ "1" = "$FORCE" ]
then
    echo "### Enabling Unattended Upgrades ###"

    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades
fi

# Configure BIND to listen on local interfaces
if [ "1" = "$INITIALIZE_BIND_CONFIG" ] || [ "1" = "$FORCE" ]
then
    echo "### Configuring BIND ###"

    sed -i "s/^\tlisten-on-v6 { any; };/\tlisten-on-v6 { ::1; };\n\tlisten-on { 127.0.0.1; };/" /etc/bind/named.conf.options
    restart_service bind9

    if [ -f /etc/dhcp/dhclient.conf ]
    then
         grep -q '^supersede domain-name-servers 127.0.0.1;' /etc/dhcp/dhclient.conf || \
             echo "supersede domain-name-servers 127.0.0.1;" >> /etc/dhcp/dhclient.conf
    fi

    if ! grep -q '^nameserver 127.0.0.1' /etc/resolv.conf
    then
        cp -a /etc/resolv.conf "/etc/resolv.conf.backup.$(date +'%Y-%m-%d-%H%M%S')"
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
    fi
fi

##########BEGIN# Create macro and acl files to /etc/exim4/ ##########
if [ ! -f /etc/exim4/exim4.conf.localmacros ] || [ "1" = "$FORCE" ]
then
    cat > /etc/exim4/exim4.conf.localmacros <<- "EOF"
	CHECK_RCPT_LOCAL_ACL_FILE = /etc/exim4/check_rcpt_local_acl
	CHECK_DATA_LOCAL_ACL_FILE = /etc/exim4/check_data_local_acl

	# Tarpit spam at really high scores.
	# Comment out to disable spam tarpitting.
	SPAM_TARPIT_SCORE = 30

	# Reject spam at high scores.
	# Comment out to disable spam rejection.
	SPAM_REJECT_SCORE = 15

	# Greylist messages with scores higher than this.
	# Comment out to disable greylisting.
	SPAM_GREYLIST_SCORE = 2

	# Comment out the next line, if this server is a relay and your
	# primary server doesn't support recipient verification.
	VERIFY_RECIPIENTS = 1

	# Enable ClamAV
	av_scanner = clamd:/var/run/clamav/clamd.ctl
	EOF
    chown root:root /etc/exim4/exim4.conf.localmacros
    chmod 644 /etc/exim4/exim4.conf.localmacros
fi

if [ ! -f /etc/exim4/check_rcpt_local_acl ] || [ "1" = "$FORCE" ]
then
    cat > /etc/exim4/check_rcpt_local_acl <<- "EOF"
	.ifdef VERIFY_RECIPIENTS
	# Verify recipient
	  deny
	    log_message = Verifying recipient failed for ${local_part}@${domain}
	    !acl = acl_local_deny_exceptions
	    !verify = recipient/callout=20s,defer_ok,random
	.endif

	# Perform greylisting on incoming messages from remote hosts.
	#
	# We also check the local whitelist to avoid greylisting mail from
	# hosts that are expected to forward mail here (such as backup MX hosts,
	# list servers, etc).
	#
	  warn
	    !hosts         = : +relay_from_hosts : \
	                     ${if exists {/etc/greylistd/whitelist-hosts}\
	                                 {/etc/greylistd/whitelist-hosts}{}} : \
	                     ${if exists {/var/lib/greylistd/whitelist-hosts}\
	                                 {/var/lib/greylistd/whitelist-hosts}{}}
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    domains        = +local_domains : +relay_to_domains
	    condition      = ${readsocket{/var/run/greylistd/socket}\
	                                 {--grey \
	                                  $sender_host_address \
	                                  $sender_address \
	                                  $local_part@$domain}\
	                                 {5s}{}{false}}
	    set acl_m_greylisted = 1
	EOF
    chown root:root /etc/exim4/check_rcpt_local_acl
    chmod 644 /etc/exim4/check_rcpt_local_acl
fi

if [ ! -f /etc/exim4/check_data_local_acl ] || [ "1" = "$FORCE" ]
then
    cat > /etc/exim4/check_data_local_acl <<- "EOF"
	# Malware check
	  deny
	    message        = This message was detected as possible malware ($malware_name).
	    log_message    = Malware ($malware_name) for $recipients
	    malware        = *

	.ifdef SPAM_TARPIT_SCORE
	# Tarpit spam
	  defer
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    spam           = Debian-exim:true
	    condition      = ${if >{$spam_score_int}{${eval10:10*${sg{SPAM_TARPIT_SCORE}{[.].*}{}}}}{1}{0}}
	    delay          = 900s
	    message        = Please try again later
	    log_message    = spam tarpitted (score $spam_score) from <$sender_address> to <$recipients>.
	.endif

	.ifdef SPAM_REJECT_SCORE
	# Permanently reject spam
	  deny
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    spam           = Debian-exim:true
	    condition      = ${if >{$spam_score_int}{${eval10:10*${sg{SPAM_REJECT_SCORE}{[.].*}{}}}}{1}{0}}
	    message        = Spam score too high ($spam_score)
	    log_message    = spam rejected (score $spam_score) from <$sender_address> to <$recipients>.
	.endif

	.ifdef SPAM_GREYLIST_SCORE
	# Temporarily reject greylisted
	  defer
	    message        = $sender_host_address is not yet authorized to deliver \
	                     mail from <$sender_address> to <$recipients>. \
	                     Please try later.
	    log_message    = greylisted (score $spam_score) from <$sender_address> to <$recipients>.
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    spam           = Debian-exim:true
	    condition      = ${if >={$spam_score_int}{${eval10:10*${sg{SPAM_GREYLIST_SCORE}{[.].*}{}}}}{1}{0}}
	    condition      = ${if eq {${acl_m_greylisted}}{1} }
	.endif

	  warn
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    spam           = Debian-exim:true
	    add_header     = X-Spam-Score: $spam_score ($spam_bar)
	    add_header     = X-Spam-Status: $spam_report

	  warn
	    !authenticated = *
	    !acl           = acl_local_deny_exceptions
	    spam           = Debian-exim
	    add_header     = X-Spam-Flag: YES
	EOF
    chown root:root /etc/exim4/check_data_local_acl
    chmod 644 /etc/exim4/check_data_local_acl
fi
##########END# Create macro and acl files to /etc/exim4/ ##########

# Generate Exim configuration files and restart the services.
restart_service spamassassin
restart_service clamav-daemon
/usr/sbin/update-exim4.conf
restart_service exim4

echo "All done!"
