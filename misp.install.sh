#!/usr/bin/env bash
#### BEGIN AUTOMATED SECTION ####

# Extract debian flavour
checkFlavour () {
  FLAVOUR=""
  # Every system that we officially support has /etc/os-release
  if [ -r /etc/os-release ]; then
    FLAVOUR="$(. /etc/os-release && echo "$ID"| tr '[:upper:]' '[:lower:]')"
  fi

  case "${FLAVOUR}" in
    ubuntu)
      if command_exists lsb_release; then
        dist_version="$(lsb_release --codename | cut -f2)"
      fi
      if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
        dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
      fi
    ;;
    debian|raspbian)
      dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
      case "$dist_version" in
        10)
          dist_version="buster"
        ;;
        9)
          dist_version="stretch"
        ;;
      esac
    ;;
    centos)
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
        dist_version=${dist_version:0:1}
      fi
      echo "${FLAVOUR} support is experimental at the moment"
    ;;
    rhel|ol|sles)
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
	dist_version=${dist_version:0:1}  # Only interested about major version
      fi
      # Only tested for RHEL 7 so far 
      echo "${FLAVOUR} support is experimental at the moment"
    ;;
    *)
      if command_exists lsb_release; then
        dist_version="$(lsb_release --release | cut -f2)"
      fi
      if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
        dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
      fi
    ;;
  esac

}


# Dynamic horizontal spacer if needed, for autonomeous an no progress bar install, we are static.
space () {
  if [[ "$NO_PROGRESS" == "1" ]] || [[ "$PACKER" == "1" ]]; then
    echo "--------------------------------------------------------------------------------"
    return
  fi
  # Check terminal width
  num=`tput cols`
  for i in `seq 1 $num`; do
    echo -n "-"
  done
  echo ""
}

# Spinner so the user knows something is happening
spin()
{
  if [[ "$NO_PROGRESS" == "1" ]]; then
    return
  fi
  spinner="/|\\-/|\\-"
  while :
  do
    for i in `seq 0 7`
    do
      echo -n "${spinner:$i:1}"
      echo -en "\010"
      sleep 0.$i
    done
  done
}

# Progress bar
progress () {
  progress=$[$progress+$1]
  if [[ "$NO_PROGRESS" == "1" ]] || [[ "$PACKER" == "1" ]]; then
    echo "progress=${progress}" > /tmp/INSTALL.stat
    return
  fi
  bar="#"

  # Prevent progress of overflowing
  if [[ $progress -ge 100 ]]; then
    echo -ne "#####################################################################################################  (100%)\r"
    return
  fi
  # Display progress
  for p in $(seq 1 $progress); do
    bar+="#"
    echo -ne "$bar  ($p%)\r"
  done
  echo -ne '\n'
  echo "progress=${progress}" > /tmp/INSTALL.stat
}

# Check locale
checkLocale () {
  debug "Checking Locale"
  # If locale is missing, generate and install a common UTF-8
  if [[ ! -f /etc/default/locale || $(wc -l /etc/default/locale| cut -f 1 -d\ ) -eq "1" ]]; then
    checkAptLock
    sudo DEBIAN_FRONTEND=noninteractive apt install locales -qy
    sudo sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g' /etc/locale.gen
    sudo locale-gen en_US.UTF-8
    sudo update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
  fi
}


# check is /usr/local/src is RW by misp user
checkUsrLocalSrc () {
  echo ""
  if [[ -e /usr/local/src ]]; then
    WRITEABLE=$(sudo -H -u $MISP_USER touch /usr/local/src 2> /dev/null ; echo $?)
    if [[ "$WRITEABLE" == "0" ]]; then
      echo "Good, /usr/local/src exists and is writeable as $MISP_USER"
    else
      # TODO: The below might be shorter, more elegant and more modern
      #[[ -n $KALI ]] || [[ -n $UNATTENDED ]] && echo "Just do it" 
      sudo chmod 2775 /usr/local/src
      sudo chown root:staff /usr/local/src
    fi
  else
    echo "/usr/local/src does not exist, creating."
    mkdir -p /usr/local/src
    sudo chmod 2775 /usr/local/src
    # TODO: Better handling /usr/local/src permissions
    if [[ "$(cat /etc/group |grep staff > /dev/null 2>&1)" == "0" ]]; then
      sudo chown root:staff /usr/local/src
    fi
  fi
}


setBaseURL () {
  debug "Setting Base URL"

  CONN=$(ip -br -o -4 a |grep UP |head -1 |tr -d "UP")
  IFACE=$(echo $CONN |awk {'print $1'})
  IP=$(echo $CONN |awk {'print $2'}| cut -f1 -d/)

  [[ -n ${MANUFACTURER} ]] || checkManufacturer

  if [[ "${MANUFACTURER}" != "innotek GmbH" ]] && [[ "$MANUFACTURER" != "VMware, Inc." ]] && [[ "$MANUFACTURER" != "QEMU" ]]; then
    debug "We guess that this is a physical machine and cannot reliably guess what the MISP_BASEURL might be."

    if [[ "${UNATTENDED}" != "1" ]]; then 
      echo "You can now enter your own MISP_BASEURL, if you wish to NOT do that, the MISP_BASEURL will be empty, which will work, but ideally you configure it afterwards."
      echo "Do you want to change it now? (y/n) "
      read ANSWER
      ANSWER=$(echo ${ANSWER} |tr '[:upper:]' '[:lower:]')
      if [[ "${ANSWER}" == "y" ]]; then
        if [[ ! -z ${IP} ]]; then
          echo "It seems you have an interface called ${IFACE} UP with the following IP: ${IP} - FYI"
          echo "Thus your Base URL could be: https://${IP}"
        fi
        echo "Please enter the Base URL, e.g: 'https://example.org'"
        echo ""
        echo -n "Enter Base URL: "
        read MISP_BASEURL
      else
        MISP_BASEURL='""'
      fi
    else
        MISP_BASEURL="https://misp.local"
        # Webserver configuration
        FQDN='misp.local'
    fi
  elif [[ "${KALI}" == "1" ]]; then
    MISP_BASEURL="https://misp.local"
    # Webserver configuration
    FQDN='misp.local'
  elif [[ "${MANUFACTURER}" == "innotek GmbH" ]]; then
    MISP_BASEURL='https://localhost:8443'
    IP=$(ip addr show | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}' |grep -v "127.0.0.1" |tail -1)
    sudo iptables -t nat -A OUTPUT -p tcp --dport 8443 -j DNAT --to ${IP}:443
    # Webserver configuration
    FQDN='localhost.localdomain'
  elif [[ "${MANUFACTURER}" == "VMware, Inc." ]]; then
    MISP_BASEURL='""'
    # Webserver configuration
    FQDN='misp.local'
  else
    MISP_BASEURL='""'
    # Webserver configuration
    FQDN='misp.local'
  fi
}


# Main composer function
composer () {
  sudo mkdir /var/www/.composer ; sudo chown ${WWW_USER}:${WWW_USER} /var/www/.composer
  ${SUDO_WWW} sh -c "cd ${PATH_TO_MISP}/app ; php composer.phar install"
}


# TODO: FIX somehow the alias of the function does not work
# Composer on php 7.0 does not need any special treatment the provided phar works well
alias composer70=composer
# Composer on php 7.2 does not need any special treatment the provided phar works well
alias composer72=composer
# Composer on php 7.3 does not need any special treatment the provided phar works well
alias composer73=composer

# TODO: this is probably a useless function
# Enable various core services
enableServices () {
    sudo systemctl daemon-reload
    sudo systemctl enable --now  mysql
    sudo systemctl enable --now  apache2
    sudo systemctl enable --now  redis-server
}

# TODO: check if this makes sense
# Generate rc.local
genRCLOCAL () {
  if [[ ! -e /etc/rc.local ]]; then
      echo '#!/bin/sh -e' | tee -a /etc/rc.local
      echo 'exit 0' | sudo tee -a /etc/rc.local
      chmod u+x /etc/rc.local
  fi

  sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
  sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
  sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
  sudo sed -i -e '$i \[ -f /etc/init.d/firstBoot ] && bash /etc/init.d/firstBoot\n' /etc/rc.local
}

# Run PyMISP tests
runTests () {
  echo "url = \"${MISP_BASEURL}\"
key = \"${AUTH_KEY}\"" |sudo tee ${PATH_TO_MISP}/PyMISP/tests/keys.py
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/PyMISP/

  ${SUDO_WWW} sh -c "cd $PATH_TO_MISP/PyMISP && git submodule foreach git pull origin master"
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -e $PATH_TO_MISP/PyMISP/.[fileobjects,neo,openioc,virustotal,pdfexport]
  ${SUDO_WWW} sh -c "cd $PATH_TO_MISP/PyMISP && ${PATH_TO_MISP}/venv/bin/python tests/testlive_comprehensive.py"
}

# Nuke the install, meaning remove all MISP data but no packages, this makes testing the installer faster
nuke () {
  echo -e "${RED}YOU ARE ABOUT TO DELETE ALL MISP DATA! Sleeping 10, 9, 8...${NC}"
  sleep 10
  sudo rm -rvf /usr/local/src/{misp-modules,viper,mail_to_misp,LIEF,faup}
  sudo rm -rvf /var/www/MISP
  sudo mysqladmin drop misp
  sudo mysql -e "DROP USER misp@localhost"
}

# Final function to let the user know what happened
theEnd () {
  space
  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN" |$SUDO_CMD tee /home/${MISP_USER}/mysql.txt
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"  |$SUDO_CMD tee -a /home/${MISP_USER}/mysql.txt
  echo "Authkey: $AUTH_KEY" |$SUDO_CMD tee -a /home/${MISP_USER}/MISP-authkey.txt

  # Commenting out, see: https://github.com/MISP/MISP/issues/5368
  # clear -x
  space
  echo -e "${LBLUE}MISP${NC} Installed, access here: ${MISP_BASEURL}"
  echo
  echo "User: admin@admin.test"
  echo "Password: admin"
  space
  ##[[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && echo -e "${LBLUE}MISP${NC} Dashboard, access here: ${MISP_BASEURL}:8001"
  ##[[ -n $KALI ]] || [[ -n $DASHBOARD ]] || [[ -n $ALL ]] && space
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-web installed, access here: ${MISP_BASEURL}:8888"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo -e "viper-cli configured with your ${LBLUE}MISP${NC} ${RED}Site Admin Auth Key${NC}"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "User: admin"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && echo "Password: Password1234"
  ##[[ -n $KALI ]] || [[ -n $VIPER ]] || [[ -n $ALL ]] && space
  echo -e "The following files were created and need either ${RED}protection or removal${NC} (${YELLOW}shred${NC} on the CLI)"
  echo "/home/${MISP_USER}/mysql.txt"
  echo -e "${RED}Contents:${NC}"
  cat /home/${MISP_USER}/mysql.txt
  echo "/home/${MISP_USER}/MISP-authkey.txt"
  echo -e "${RED}Contents:${NC}"
  cat /home/${MISP_USER}/MISP-authkey.txt
  space
  echo -e "The ${RED}LOCAL${NC} system credentials:"
  echo "User: ${MISP_USER}"
  echo "Password: ${MISP_PASSWORD} # Or the password you used of your custom user"
  space
  echo "GnuPG Passphrase is: ${GPG_PASSPHRASE}"
  space
  echo "To enable outgoing mails via postfix set a permissive SMTP server for the domains you want to contact:"
  echo
  echo "sudo postconf -e 'relayhost = example.com'"
  echo "sudo postfix reload"
  space
  echo -e "Enjoy using ${LBLUE}MISP${NC}. For any issues see here: https://github.com/MISP/MISP/issues"
  space
  if [[ "$UNATTENDED" == "1" ]]; then
    echo -e "${RED}Unattended install!${NC}"
    echo -e "This means we guessed the Base URL, it might be wrong, please double check."
    space
  fi

  if [[ "$PACKER" == "1" ]]; then
    echo -e "${RED}This was an Automated Packer install!${NC}"
    echo -e "This means we forced an unattended install."
    space
  fi

  if [[ "$USER" != "$MISP_USER" && "$UNATTENDED" != "1" ]]; then
    sudo su - ${MISP_USER}
  fi
}
## End Function Section Nothing allowed in .md after this line ##






prepareDB () {
  if [[ ! -e /var/lib/mysql/misp/users.ibd ]]; then
    debug "Setting up database"

    # FIXME: If user 'misp' exists, and has a different password, the below WILL fail.
    # Add your credentials if needed, if sudo has NOPASS, comment out the relevant lines
    if [[ "${PACKER}" == "1" ]]; then
      pw="Password1234"
    else
      pw=${MISP_PASSWORD}
    fi

    expect -f - <<-EOF
      set timeout 10

      spawn sudo -k mysql_secure_installation
      expect "*?assword*"
      send -- "${pw}\r"
      expect "Enter current password for root (enter for none):"
      send -- "\r"
      expect "Set root password?"
      send -- "y\r"
      expect "New password:"
      send -- "${DBPASSWORD_ADMIN}\r"
      expect "Re-enter new password:"
      send -- "${DBPASSWORD_ADMIN}\r"
      expect "Remove anonymous users?"
      send -- "y\r"
      expect "Disallow root login remotely?"
      send -- "y\r"
      expect "Remove test database and access to it?"
      send -- "y\r"
      expect "Reload privilege tables now?"
      send -- "y\r"
      expect eof
EOF
    sudo apt-get purge -y expect ; sudo apt autoremove -qy
  fi 

  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "CREATE DATABASE ${DBNAME};"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "CREATE USER '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "GRANT USAGE ON *.* to ${DBUSER_MISP}@localhost;"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -u ${DBUSER_ADMIN} -p${DBPASSWORD_ADMIN} -e "FLUSH PRIVILEGES;"
  # Import the empty MISP database from MYSQL.sql
  ${SUDO_WWW} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -u ${DBUSER_MISP} -p${DBPASSWORD_MISP} ${DBNAME}
}

apacheConfig () {
  debug "Generating Apache config, if this hangs, make sure you have enough entropy (install: haveged or wait)"
  sudo cp ${PATH_TO_MISP}/INSTALL/apache.24.misp.ssl /etc/apache2/sites-available/misp-ssl.conf

  if [[ ! -z ${MISP_BASEURL} ]] && [[ "$(echo $MISP_BASEURL|cut -f 1 -d :)" == "http" || "$(echo $MISP_BASEURL|cut -f 1 -d :)" == "https" ]]; then

    echo "Potentially replacing misp.local with $MISP_BASEURL in misp-ssl.conf"

  fi

  # If a valid SSL certificate is not already created for the server,
  # create a self-signed certificate:
  sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \
  -keyout /etc/ssl/private/misp.local.key -out /etc/ssl/private/misp.local.crt

  # Enable modules, settings, and default of SSL in Apache
  sudo a2dismod status
  sudo a2enmod ssl
  sudo a2enmod rewrite
  sudo a2enmod headers
  sudo a2dissite 000-default
  sudo a2ensite default-ssl

  # Apply all changes
  sudo systemctl restart apache2
  # activate new vhost
  sudo a2dissite default-ssl
  sudo a2ensite misp-ssl

  # Restart apache
  sudo systemctl restart apache2
}

installCore () {
  debug "Installing ${LBLUE}MISP${NC} core"
  # Download MISP using git in the /var/www/ directory.
  sudo mkdir ${PATH_TO_MISP}
  sudo chown $WWW_USER:$WWW_USER ${PATH_TO_MISP}
  cd ${PATH_TO_MISP}
  $SUDO_WWW git clone https://github.com/MISP/MISP.git ${PATH_TO_MISP}
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false

  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  $SUDO_WWW virtualenv -p python3 ${PATH_TO_MISP}/venv

  # make pip happy
  sudo mkdir /var/www/.cache/
  sudo chown $WWW_USER:$WWW_USER /var/www/.cache

  cd ${PATH_TO_MISP}/app/files/scripts
  $SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git
  $SUDO_WWW git clone https://github.com/STIXProject/python-stix.git
  $SUDO_WWW git clone https://github.com/MAECProject/python-maec.git

  # install mixbox to accommodate the new STIX dependencies:
  $SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git
  cd ${PATH_TO_MISP}/app/files/scripts/mixbox
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd ${PATH_TO_MISP}/app/files/scripts/python-cybox
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd ${PATH_TO_MISP}/app/files/scripts/python-stix
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  cd $PATH_TO_MISP/app/files/scripts/python-maec
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  # install STIX2.0 library to support STIX 2.0 export:
  cd ${PATH_TO_MISP}/cti-python-stix2
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .

  # install PyMISP
  cd ${PATH_TO_MISP}/PyMISP
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install .
  # FIXME: Remove libfaup etc once the egg has the library baked-in
  sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
  cd /tmp
  [[ ! -d "faup" ]] && $SUDO_CMD git clone git://github.com/stricaud/faup.git faup
  [[ ! -d "gtcaca" ]] && $SUDO_CMD git clone git://github.com/stricaud/gtcaca.git gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # install pydeep
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

  # install lief
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install lief

  # install zmq needed by mispzmq
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install zmq redis

  # install python-magic
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install python-magic

  # install plyara
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install plyara
}

installCake () {
  debug "Installing CakePHP"
  # Once done, install CakeResque along with its dependencies 
  # if you intend to use the built in background jobs:
  cd ${PATH_TO_MISP}/app
  # Make composer cache happy
  # /!\ composer on Ubuntu when invoked with sudo -u doesn't set $HOME to /var/www but keeps it /home/misp \!/
  sudo mkdir /var/www/.composer ; sudo chown $WWW_USER:$WWW_USER /var/www/.composer
  $SUDO_WWW php composer.phar install

  # Enable CakeResque with php-redis
  sudo phpenmod redis
  sudo phpenmod gnupg

  # To use the scheduler worker for scheduled tasks, do the following:
  $SUDO_WWW cp -fa ${PATH_TO_MISP}/INSTALL/setup/config.php ${PATH_TO_MISP}/app/Plugin/CakeResque/Config/config.php

  # If you have multiple MISP instances on the same system, don't forget to have a different Redis per MISP instance for the CakeResque workers
  # The default Redis port can be updated in Plugin/CakeResque/Config/config.php
}

# Main function to fix permissions to something sane
permissions () {
  debug "Setting permissions"
  sudo chown -R ${WWW_USER}:${WWW_USER} ${PATH_TO_MISP}
  sudo chmod -R 750 ${PATH_TO_MISP}
  sudo chmod -R g+ws ${PATH_TO_MISP}/app/tmp
  sudo chmod -R g+ws ${PATH_TO_MISP}/app/files
  sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
}

configMISP () {
  debug "Generating ${LBLUE}MISP${NC} config files"
  # There are 4 sample configuration files in ${PATH_TO_MISP}/app/Config that need to be copied
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/bootstrap.default.php ${PATH_TO_MISP}/app/Config/bootstrap.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/database.default.php ${PATH_TO_MISP}/app/Config/database.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/core.default.php ${PATH_TO_MISP}/app/Config/core.php
  $SUDO_WWW cp -a ${PATH_TO_MISP}/app/Config/config.default.php ${PATH_TO_MISP}/app/Config/config.php

  echo "<?php
  class DATABASE_CONFIG {
          public \$default = array(
                  'datasource' => 'Database/Mysql',
                  //'datasource' => 'Database/Postgres',
                  'persistent' => false,
                  'host' => '$DBHOST',
                  'login' => '$DBUSER_MISP',
                  'port' => 3306, // MySQL & MariaDB
                  //'port' => 5432, // PostgreSQL
                  'password' => '$DBPASSWORD_MISP',
                  'database' => '$DBNAME',
                  'prefix' => '',
                  'encoding' => 'utf8',
          );
  }" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php

  # Important! Change the salt key in ${PATH_TO_MISP}/app/Config/config.php
  # The salt key must be a string at least 32 bytes long.
  # The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
  # If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
  # delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

  # and make sure the file permissions are still OK
  sudo chown -R $WWW_USER:$WWW_USER ${PATH_TO_MISP}/app/Config
  sudo chmod -R 750 ${PATH_TO_MISP}/app/Config
}

# Core cake commands to tweak MISP and aleviate some of the configuration pains
# The $RUN_PHP is ONLY set on RHEL/CentOS installs and can thus be ignored
# This file is NOT an excuse to NOT read the settings and familiarize ourselves with them ;)

coreCAKE () {
  debug "Running core Cake commands to set sane defaults for ${LBLUE}MISP${NC}"

  # IF you have logged in prior to running this, it will fail but the fail is NON-blocking
  $SUDO_WWW $RUN_PHP -- $CAKE userInit -q

  # This makes sure all Database upgrades are done, without logging in.
  $SUDO_WWW $RUN_PHP -- $CAKE Admin runUpdates

  # The default install is Python >=3.6 in a virtualenv, setting accordingly
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python"

  # Set default role
  # TESTME: The following seem defunct, please test.
  # $SUDO_WWW $RUN_PHP -- $CAKE setDefaultRole 3

  # Tune global time outs
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.autoRegenerate" 0
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.timeout" 600
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Session.cookieTimeout" 3600

  # Change base url, either with this CLI command or in the UI
  $SUDO_WWW $RUN_PHP -- $CAKE Baseurl $MISP_BASEURL
  # example: 'baseurl' => 'https://<your.FQDN.here>',
  # alternatively, you can leave this field empty if you would like to use relative pathing in MISP
  # 'baseurl' => '',
  # The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs.
  # MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.external_baseurl" $MISP_BASEURL

  # Enable GnuPG
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.email" "$GPG_EMAIL_ADDRESS"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.homedir" "$PATH_TO_MISP/.gnupg"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.password" "$GPG_PASSPHRASE"
  # FIXME: what if we have not gpg binary but a gpg2 one?
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "GnuPG.binary" "$(which gpg)"

  # Enable installer org and tune some configurables
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.host_org_id" 1
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.email" "info@admin.test"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disable_emailing" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.contact" "info@admin.test"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disablerestalert" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.default_event_tag_collection" 0

  # Provisional Cortex tunes
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_enable" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_timeout" 120
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_authkey" ""
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

  # Various plugin sightings settings
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_policy" 0
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_anonymise" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_range" 365
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Sightings_sighting_db_enable" false

  # Plugin CustomAuth tuneable
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false

  # RPZ Plugin settings
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_retry" "30m"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost."
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_ns_alt" ""
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost"

  # Force defaults to make MISP Server Settings less RED
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.language" "eng"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.proposals_block_attributes" false

  # Redis block
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_port" 6379
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_database" 13
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.redis_password" ""

  # Force defaults to make MISP Server Settings less YELLOW
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.extended_alert_subject" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.default_event_threat_level" 4
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.enableEventBlacklisting" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.log_client_ip" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.log_auth" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.disableUserSelfManagement" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_event_alert" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_old_event_alert" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_old_event_alert_age" ""
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.block_old_event_alert_by_date" ""
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.maintenance_message" "Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at \$email."
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.footermidleft" "This is an initial install"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
  # TODO: Make sure $FLAVOUR is correct
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP on $FLAVOUR, change this message in MISP Settings"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.attachments_dir" "$PATH_TO_MISP/app/files"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.download_attachments_on_load" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.title_text" "MISP"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.terms_download" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.showorgalternate" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "MISP.event_view_filter_fields" "id, uuid, value, comment, type, category, Tag.name"

  # Force defaults to make MISP Server Settings less GREEN
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Security.password_policy_length" 12
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Security.self_registration_message" "If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators."

  # It is possible to updateMISP too, only here for reference how to to that on the CLI.
  ## $SUDO_WWW $RUN_PHP -- $CAKE Admin updateMISP

  # Set MISP Live
  $SUDO_WWW $RUN_PHP -- $CAKE Live $MISP_LIVE
}

# This updates Galaxies, ObjectTemplates, Warninglists, Noticelists, Templates
updateGOWNT () {
  # AUTH_KEY Place holder in case we need to **curl** somehing in the future
  # 
  $SUDO_WWW $RUN_MYSQL -- mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1 > /tmp/auth.key
  AUTH_KEY=$(cat /tmp/auth.key)
  rm /tmp/auth.key

  debug "Updating Galaxies, ObjectTemplates, Warninglists, Noticelists and Templates"
  # Update the galaxies…
  # TODO: Fix updateGalaxies
  $SUDO_WWW $RUN_PHP -- $CAKE Admin updateGalaxies
  # Updating the taxonomies…
  $SUDO_WWW $RUN_PHP -- $CAKE Admin updateTaxonomies
  # Updating the warning lists…
  $SUDO_WWW $RUN_PHP -- $CAKE Admin updateWarningLists
  # Updating the notice lists…
  $SUDO_WWW $RUN_PHP -- $CAKE Admin updateNoticeLists
  # Updating the object templates…
  $SUDO_WWW $RUN_PHP -- $CAKE Admin updateObjectTemplates "1337"
}

# Generate GnuPG key
setupGnuPG () {
  if [ ! -d $PATH_TO_MISP/.gnupg ]; then
    # The email address should match the one set in the config.php
    # set in the configuration menu in the administration menu configuration file
    echo "%echo Generating a default key
      Key-Type: default
      Key-Length: $GPG_KEY_LENGTH
      Subkey-Type: default
      Name-Real: $GPG_REAL_NAME
      Name-Comment: $GPG_COMMENT
      Name-Email: $GPG_EMAIL_ADDRESS
      Expire-Date: 0
      Passphrase: $GPG_PASSPHRASE
      # Do a commit here, so that we can later print "done"
      %commit
    %echo done" > /tmp/gen-key-script

    $SUDO_WWW gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script

    # Export the public key to the webroot
    $SUDO_WWW sh -c "gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS" | $SUDO_WWW tee $PATH_TO_MISP/app/webroot/gpg.asc
  fi
}

logRotation () {
  # MISP saves the stdout and stderr of its workers in ${PATH_TO_MISP}/app/tmp/logs
  # To rotate these logs install the supplied logrotate script:
  sudo cp ${PATH_TO_MISP}/INSTALL/misp.logrotate /etc/logrotate.d/misp
  sudo chmod 0640 /etc/logrotate.d/misp
}

backgroundWorkers () {
  debug "Setting up background workers"
  # To make the background workers start on boot
  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh

  if [ ! -e /etc/rc.local ]
  then
      echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local
      echo 'exit 0' | sudo tee -a /etc/rc.local
      sudo chmod u+x /etc/rc.local
  fi

  echo "[Unit]
Description=MISP background workers
After=network.target

[Service]
Type=forking
User=${WWW_USER}
Group=${WWW_USER}
ExecStart=${PATH_TO_MISP}/app/Console/worker/start.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/misp-workers.service

  sudo systemctl daemon-reload
  sudo systemctl enable --now misp-workers

  # Add the following lines before the last line (exit 0). Make sure that you replace www-data with your apache user:
  sudo sed -i -e '$i \echo never > /sys/kernel/mm/transparent_hugepage/enabled\n' /etc/rc.local
  sudo sed -i -e '$i \echo 1024 > /proc/sys/net/core/somaxconn\n' /etc/rc.local
  sudo sed -i -e '$i \sysctl vm.overcommit_memory=1\n' /etc/rc.local
}

# Main MISP Modules install function
mispmodules () {
  cd /usr/local/src/
  sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
  ## TODO: checkUsrLocalSrc in main doc
  debug "Cloning misp-modules"
  false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/MISP/misp-modules.git; done
  [[ ! -d "faup" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone git://github.com/stricaud/faup.git faup; done
  [[ ! -d "gtcaca" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone git://github.com/stricaud/gtcaca.git gtcaca; done
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  # Install gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  # Install faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig
  cd ../../misp-modules
  # some misp-modules dependencies
  sudo apt install libpq5 libjpeg-dev tesseract-ocr libpoppler-cpp-dev imagemagick libopencv-dev zbar-tools libzbar0 libzbar-dev libfuzzy-dev -y
  # If you build an egg, the user you build it as need write permissions in the CWD
  sudo chgrp $WWW_USER .
  sudo chmod og+w .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
  sudo chgrp staff .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I .
  ## sudo gem install asciidoctor-pdf --pre

  # Start misp-modules as a service
  sudo cp etc/systemd/system/misp-modules.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now misp-modules

  # Sleep 9 seconds to give misp-modules a chance to spawn
  sleep 9

  # Enable Enrichment, set better timeouts
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
  # TODO:"Investigate why the next one fails"
  #$SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_btc_steroids_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_ipasn_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_yara_syntax_validator_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_yara_query_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_pdf_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_docx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_xlsx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_pptx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_ods_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_odt_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules, set better timeout
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_port" 6666
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_mispjson_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_openiocimport_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_threatanalyzer_import_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

  # Enable Export modules, set better timeout
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_port" 6666
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true
}

# Main MISP Dashboard install function
mispDashboard () {
  debug "Install misp-dashboard"
  # Install pyzmq to main MISP venv
  debug "Installing PyZMQ"
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install pyzmq
  cd /var/www
  sudo mkdir misp-dashboard
  sudo chown $WWW_USER:$WWW_USER misp-dashboard

  false; while [[ $? -ne 0 ]]; do $SUDO_WWW git clone https://github.com/MISP/misp-dashboard.git; done
  cd misp-dashboard
  sudo -H /var/www/misp-dashboard/install_dependencies.sh
  sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
  sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/apache2/ports.conf
  sudo apt install libapache2-mod-wsgi-py3 net-tools -y
  echo "<VirtualHost *:8001>
      ServerAdmin admin@misp.local
      ServerName misp.local

      DocumentRoot /var/www/misp-dashboard

      WSGIDaemonProcess misp-dashboard \
         user=misp group=misp \
         python-home=/var/www/misp-dashboard/DASHENV \
         processes=1 \
         threads=15 \
         maximum-requests=5000 \
         listen-backlog=100 \
         queue-timeout=45 \
         socket-timeout=60 \
         connect-timeout=15 \
         request-timeout=60 \
         inactivity-timeout=0 \
         deadlock-timeout=60 \
         graceful-timeout=15 \
         eviction-timeout=0 \
         shutdown-timeout=5 \
         send-buffer-size=0 \
         receive-buffer-size=0 \
         header-buffer-size=0 \
         response-buffer-size=0 \
         server-metrics=Off

      WSGIScriptAlias / /var/www/misp-dashboard/misp-dashboard.wsgi

      <Directory /var/www/misp-dashboard>
          WSGIProcessGroup misp-dashboard
          WSGIApplicationGroup %{GLOBAL}
          Require all granted
      </Directory>

      LogLevel info
      ErrorLog /var/log/apache2/misp-dashboard.local_error.log
      CustomLog /var/log/apache2/misp-dashboard.local_access.log combined
      ServerSignature Off
  </VirtualHost>" | sudo tee /etc/apache2/sites-available/misp-dashboard.conf

  # Enable misp-dashboard in apache and reload
  sudo a2ensite misp-dashboard
  sudo systemctl restart apache2

  # Needs to be started after apache2 is reloaded so the port status check works
  $SUDO_WWW bash /var/www/misp-dashboard/start_all.sh

  # Add misp-dashboard to rc.local to start on boot.
  sudo sed -i -e '$i \sudo -u www-data bash /var/www/misp-dashboard/start_all.sh > /tmp/misp-dashboard_rc.local.log\n' /etc/rc.local
}

dashboardCAKE () {
  # Enable ZeroMQ for misp-dashboard
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_port" 50000
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
}

# Main mail2misp install function
mail2misp () {
  debug "Installing Mail2${LBLUE}MISP${NC}"
  cd /usr/local/src/
  sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
  false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/MISP/mail_to_misp.git; done
  ## TODO: The below fails miserably (obviously) if faup/gtcac dirs exist, let's just make the dangerous assumption (for the sake of the installer, that they exist)
  ##[[ ! -d "faup" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone git://github.com/stricaud/faup.git faup; done
  ##[[ ! -d "gtcaca" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone git://github.com/stricaud/gtcaca.git gtcaca; done
  sudo chown -R ${MISP_USER}:${MISP_USER} faup mail_to_misp gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig
  cd ../../mail_to_misp
  $SUDO_CMD virtualenv -p python3 venv
  $SUDO_CMD ./venv/bin/pip install lief
  $SUDO_CMD ./venv/bin/pip install -r requirements.txt
  $SUDO_CMD cp mail_to_misp_config.py-example mail_to_misp_config.py
  ##$SUDO cp mail_to_misp_config.py-example mail_to_misp_config.py
  $SUDO_CMD sed -i "s/^misp_url\ =\ 'YOUR_MISP_URL'/misp_url\ =\ 'https:\/\/localhost'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
  $SUDO_CMD sed -i "s/^misp_key\ =\ 'YOUR_KEY_HERE'/misp_key\ =\ '${AUTH_KEY}'/g" /usr/local/src/mail_to_misp/mail_to_misp_config.py
}

ssdeep () {
  debug "Install ssdeep 2.14.1"
  cd /usr/local/src
  $SUDO_CMD wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
  $SUDO_CMD tar zxvf ssdeep-2.14.1.tar.gz
  cd ssdeep-2.14.1
  $SUDO_CMD ./configure --datadir=/usr --prefix=/usr --localstatedir=/var --sysconfdir=/etc
  $SUDO_CMD make
  sudo make install

  #installing ssdeep_php
  sudo pecl channel-update pecl.php.net
  sudo pecl install ssdeep

  # You should add "extension=ssdeep.so" to mods-available - Check /etc/php for your current version
  echo "extension=ssdeep.so" | sudo tee ${PHP_ETC_BASE}/mods-available/ssdeep.ini
  sudo phpenmod ssdeep
  sudo service apache2 restart
}

# viper-web is broken ATM
# Main Viper install function
viper () {
  export PATH=$PATH:/home/misp/.local/bin
  debug "Installing Viper dependencies"
  cd /usr/local/src/
  sudo apt-get install \
    libssl-dev swig python3-ssdeep p7zip-full unrar-free sqlite python3-pyclamd exiftool radare2 \
    python3-magic python3-sqlalchemy python3-prettytable libffi-dev libfreetype6-dev libpng-dev -qy
  if [[ -f "/etc/debian_version" ]]; then
    if [[ "$(cat /etc/debian_version)" == "9.9" ]]; then
      sudo apt-get install libpython3.5-dev -qy
    fi
  fi
  echo "Cloning Viper"
  false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/viper-framework/viper.git; done
  false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/viper-framework/viper-web.git; done
  sudo chown -R $MISP_USER:$MISP_USER viper
  sudo chown -R $MISP_USER:$MISP_USER viper-web
  cd viper
  echo "Creating virtualenv"
  $SUDO_CMD virtualenv -p python3 venv
  echo "Submodule update"
  # TODO: Check for current user install permissions
  $SUDO_CMD git submodule update --init --recursive
  echo "pip install deps"
  $SUDO_CMD ./venv/bin/pip install pefile olefile jbxapi Crypto pypdns pypssl r2pipe pdftools virustotal-api SQLAlchemy PrettyTable python-magic scrapy lief
  $SUDO_CMD ./venv/bin/pip install .
  echo 'update-modules' |/usr/local/src/viper/venv/bin/viper
  cd /usr/local/src/viper-web
  $SUDO_CMD sed -i '1 s/^.*$/\#!\/usr\/local\/src\/viper\/venv\/bin\/python/' viper-web
  $SUDO_CMD /usr/local/src/viper/venv/bin/pip install -r requirements.txt
  echo "Launching viper-web"
  $SUDO_CMD /usr/local/src/viper-web/viper-web -p 8888 -H 0.0.0.0 &
  echo 'PATH="/home/misp/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/src/viper:/var/www/MISP/app/Console"' |sudo tee -a /etc/environment
  echo ". /etc/environment" >> /home/${MISP_USER}/.profile

  # TODO: Perms, MISP_USER_HOME, nasty hack cuz Kali on R00t
  if [ -f /home/${MISP_USER}/.viper/viper.conf ]; then
    VIPER_HOME="/home/${MISP_USER}/.viper"
  else
    VIPER_HOME="${HOME}/.viper"
  fi

  echo "Setting misp_url/misp_key"
  $SUDO_CMD sed -i "s/^misp_url\ =/misp_url\ =\ http:\/\/localhost/g" ${VIPER_HOME}/viper.conf
  $SUDO_CMD sed -i "s/^misp_key\ =/misp_key\ =\ $AUTH_KEY/g" ${VIPER_HOME}/viper.conf
  # Reset admin password to: admin/Password1234
  echo "Fixing admin.db with default password"
  VIPER_COUNT=0
  while [ "$(sudo sqlite3 ${VIPER_HOME}/admin.db 'UPDATE auth_user SET password="pbkdf2_sha256$100000$iXgEJh8hz7Cf$vfdDAwLX8tko1t0M1TLTtGlxERkNnltUnMhbv56wK/U="'; echo $?)" -ne "0" ]; do
    # FIXME This might lead to a race condition, the while loop is sub-par
    sudo chown $MISP_USER:$MISP_USER ${VIPER_HOME}/admin.db
    echo "Updating viper-web admin password, giving process time to start-up, sleeping 5, 4, 3,…"
    sleep 6
    VIPER_COUNT=$[$VIPER_COUNT+1]
    if [[ "$VIPER_COUNT" > '10' ]]; then
      echo "Something is wrong with updating viper. Continuing without db update."
      break
    fi
  done

  # Add viper-web to rc.local to be started on boot
  sudo sed -i -e '$i \sudo -u misp /usr/local/src/viper/viper-web -p 8888 -H 0.0.0.0 > /tmp/viper-web_rc.local.log &\n' /etc/rc.local
}


enableReposRHEL () {
  sudo subscription-manager refresh
  sudo subscription-manager repos --enable rhel-7-server-optional-rpms
  sudo subscription-manager repos --enable rhel-7-server-extras-rpms
  sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
}

centosEPEL () {
  # We need some packages from the Extra Packages for Enterprise Linux repository
  sudo yum install epel-release -y

  # Since MISP 2.4 PHP 5.5 is a minimal requirement, so we need a newer version than CentOS base provides
  # Software Collections is a way do to this, see https://wiki.centos.org/AdditionalResources/Repositories/SCL
  sudo yum install centos-release-scl -y
}

enableEPEL () {
  sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
}

yumInstallCoreDeps () {
  # Install the dependencies:
  sudo yum install gcc git zip rh-git218 \
                   httpd24 \
                   mod_ssl \
                   rh-redis32 \
                   rh-mariadb102 \
                   libxslt-devel zlib-devel ssdeep-devel -y

  # Enable and start redis
  sudo systemctl enable --now rh-redis32-redis.service

  WWW_USER="apache"
  SUDO_WWW="sudo -H -u $WWW_USER"
  RUN_PHP="/usr/bin/scl enable rh-php72"
  PHP_INI="/etc/opt/rh/rh-php72/php.ini"
  # Install PHP 7.2 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php72/
  sudo yum install rh-php72 rh-php72-php-fpm rh-php72-php-devel \
                   rh-php72-php-mysqlnd \
                   rh-php72-php-mbstring \
                   rh-php72-php-xml \
                   rh-php72-php-bcmath \
                   rh-php72-php-opcache \
                   rh-php72-php-gd -y

  # Python 3.6 is now available in RHEL 7.7 base
  sudo yum install python3 python3-devel -y

  sudo systemctl enable --now rh-php72-php-fpm.service
}

installCoreRHEL () {
  # Download MISP using git in the $PATH_TO_MISP directory.
  sudo mkdir -p $(dirname $PATH_TO_MISP)
  sudo chown $WWW_USER:$WWW_USER $(dirname $PATH_TO_MISP)
  cd $(dirname $PATH_TO_MISP)
  $SUDO_WWW git clone https://github.com/MISP/MISP.git
  cd $PATH_TO_MISP
  ##$SUDO_WWW git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
  # if the last shortcut doesn't work, specify the latest version manually
  # example: git checkout tags/v2.4.XY
  # the message regarding a "detached HEAD state" is expected behaviour
  # (you only have to create a new branch, if you want to change stuff and do a pull request for example)

  # Fetch submodules
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false
  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  sudo pip3 install virtualenv
  $SUDO_WWW python3 -m venv $PATH_TO_MISP/venv
  sudo mkdir /usr/share/httpd/.cache
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.cache
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

  cd $PATH_TO_MISP/app/files/scripts
  $SUDO_WWW git clone https://github.com/CybOXProject/python-cybox.git
  $SUDO_WWW git clone https://github.com/STIXProject/python-stix.git
  $SUDO_WWW git clone --branch master --single-branch https://github.com/lief-project/LIEF.git lief
  $SUDO_WWW git clone https://github.com/CybOXProject/mixbox.git

  # If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
  UMASK=$(umask)
  umask 0022
  
  cd $PATH_TO_MISP/app/files/scripts/python-cybox
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .
  
  cd $PATH_TO_MISP/app/files/scripts/python-stix
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

  # install mixbox to accommodate the new STIX dependencies:
  cd $PATH_TO_MISP/app/files/scripts/mixbox
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

  # install STIX2.0 library to support STIX 2.0 export:
  cd $PATH_TO_MISP/cti-python-stix2
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install .

  # install maec
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U maec

  # install zmq
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U zmq

  # install redis
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U redis

  # lief needs manual compilation
  sudo yum install devtoolset-7 cmake3 cppcheck libcxx-devel -y

  cd $PATH_TO_MISP/app/files/scripts/lief
  $SUDO_WWW mkdir build
  cd build
  $SUDO_WWW scl enable devtoolset-7 "bash -c 'cmake3 \
  -DLIEF_PYTHON_API=on \
  -DPYTHON_VERSION=3.6 \
  -DPYTHON_EXECUTABLE=$PATH_TO_MISP/venv/bin/python \
  -DLIEF_DOC=off \
  -DCMAKE_BUILD_TYPE=Release \
  ..'"
  $SUDO_WWW make -j3 pyLIEF

  if [ $? == 2 ]; then
    # In case you get "internal compiler error: Killed (program cc1plus)"
    # You ran out of memory.
    # Create some swap
    sudo dd if=/dev/zero of=/var/swap.img bs=1024k count=4000
    sudo mkswap /var/swap.img
    sudo swapon /var/swap.img
    # And compile again
    $SUDO_WWW make -j3 pyLIEF
    sudo swapoff /var/swap.img
    sudo rm /var/swap.img
  fi

  # The following adds a PYTHONPATH to where the pyLIEF module has been compiled
  echo $PATH_TO_MISP/app/files/scripts/lief/build/api/python |$SUDO_WWW tee $PATH_TO_MISP/venv/lib/python3.6/site-packages/lief.pth

  # install magic, pydeep
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic git+https://github.com/kbandla/pydeep.git plyara

  # install PyMISP
  cd $PATH_TO_MISP/PyMISP
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U .

  # FIXME: Remove libfaup etc once the egg has the library baked-in
  # BROKEN: This needs to be tested on RHEL/CentOS
  ##sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
  cd /tmp
  [[ ! -d "faup" ]] && $SUDO_CMD git clone git://github.com/stricaud/faup.git faup
  [[ ! -d "gtcaca" ]] && $SUDO_CMD git clone git://github.com/stricaud/gtcaca.git gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # Enable dependencies detection in the diagnostics page
  # This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
  # The LD_LIBRARY_PATH setting is needed for rh-git218 to work
  echo "env[PATH] = /opt/rh/rh-git218/root/usr/bin:/opt/rh/rh-redis32/root/usr/bin:/opt/rh/rh-php72/root/usr/bin:/usr/local/bin:/usr/bin:/bin" |sudo tee -a /etc/opt/rh/rh-php72/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php72/php-fpm.d/www.conf
  sudo systemctl restart rh-php72-php-fpm.service
  umask $UMASK
}

installCake_RHEL ()
{
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  sudo mkdir /usr/share/httpd/.composer
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.composer
  cd $PATH_TO_MISP/app
  # Update composer.phar (optional)
  #EXPECTED_SIGNATURE="$(wget -q -O - https://composer.github.io/installer.sig)"
  #$SUDO_WWW $RUN_PHP -- php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
  #$SUDO_WWW $RUN_PHP -- php -r "if (hash_file('SHA384', 'composer-setup.php') === '$EXPECTED_SIGNATURE') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
  #$SUDO_WWW $RUN_PHP "php composer-setup.php"
  #$SUDO_WWW $RUN_PHP -- php -r "unlink('composer-setup.php');"
  $SUDO_WWW $RUN_PHP "php composer.phar install"

  ## sudo yum install php-redis -y
  sudo scl enable rh-php72 'pecl channel-update pecl.php.net'
  sudo scl enable rh-php72 'yes no|pecl install redis'
  echo "extension=redis.so" |sudo tee /etc/opt/rh/rh-php72/php.d/99-redis.ini

  sudo ln -s /usr/lib64/libfuzzy.so /usr/lib/libfuzzy.so
  sudo scl enable rh-php72 'pecl install ssdeep'
  echo "extension=ssdeep.so" |sudo tee /etc/opt/rh/rh-php72/php.d/99-ssdeep.ini

  # Install gnupg extension
  sudo yum install gpgme-devel -y
  sudo scl enable rh-php72 'pecl install gnupg'
  echo "extension=gnupg.so" |sudo tee /etc/opt/rh/rh-php72/php.d/99-gnupg.ini
  sudo systemctl restart rh-php72-php-fpm.service

  # If you have not yet set a timezone in php.ini
  echo 'date.timezone = "Asia/Tokyo"' |sudo tee /etc/opt/rh/rh-php72/php.d/timezone.ini

  # Recommended: Change some PHP settings in /etc/opt/rh/rh-php72/php.ini
  # max_execution_time = 300
  # memory_limit = 2048M
  # upload_max_filesize = 50M
  # post_max_size = 50M
  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
  sudo systemctl restart rh-php72-php-fpm.service

  # To use the scheduler worker for scheduled tasks, do the following:
  sudo cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
}

prepareDB_RHEL () {
  RUN_MYSQL="/usr/bin/scl enable rh-mariadb102"
  # Enable, start and secure your mysql database server
  sudo systemctl enable --now rh-mariadb102-mariadb.service
  echo [mysqld] |sudo tee /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
  echo bind-address=127.0.0.1 |sudo tee -a /etc/opt/rh/rh-mariadb102/my.cnf.d/bind-address.cnf
  sudo systemctl restart rh-mariadb102-mariadb

  sudo yum install expect -y

  ## The following needs some thoughts about scl enable foo
  #if [[ ! -e /var/opt/rh/rh-mariadb102/lib/mysql/misp/users.ibd ]]; then

  # We ask interactively your password if not run as root
  pw=""
  if [[ "$EUID" -ne 0 ]]; then
    read -s -p "Enter sudo password: " pw
  fi

  expect -f - <<-EOF
    set timeout 10

    spawn sudo scl enable rh-mariadb102 mysql_secure_installation
    expect {
      "*sudo*" {
        send "$pw\r"
        exp_continue
      }
      "Enter current password for root (enter for none):" {
        send -- "\r"
      }
    }
    expect "Set root password?"
    send -- "y\r"
    expect "New password:"
    send -- "${DBPASSWORD_ADMIN}\r"
    expect "Re-enter new password:"
    send -- "${DBPASSWORD_ADMIN}\r"
    expect "Remove anonymous users?"
    send -- "y\r"
    expect "Disallow root login remotely?"
    send -- "y\r"
    expect "Remove test database and access to it?"
    send -- "y\r"
    expect "Reload privilege tables now?"
    send -- "y\r"
    expect eof
EOF

  sudo yum remove tcl expect -y

  sudo systemctl restart rh-mariadb102-mariadb

  scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e 'CREATE DATABASE $DBNAME;'"
  scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e \"GRANT USAGE on *.* to $DBUSER_MISP@localhost IDENTIFIED by '$DBPASSWORD_MISP';\""
  scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e \"GRANT ALL PRIVILEGES on $DBNAME.* to '$DBUSER_MISP'@'localhost';\""
  scl enable rh-mariadb102 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e 'FLUSH PRIVILEGES;'"

  $SUDO_WWW cat $PATH_TO_MISP/INSTALL/MYSQL.sql | sudo scl enable rh-mariadb102 "mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME"
}

apacheConfig_RHEL () {
  # Now configure your apache server with the DocumentRoot $PATH_TO_MISP/app/webroot/
  # A sample vhost can be found in $PATH_TO_MISP/INSTALL/apache.misp.centos7

  sudo cp $PATH_TO_MISP/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf
  #sudo sed -i "s/SetHandler/\#SetHandler/g" /etc/httpd/conf.d/misp.ssl.conf
  sudo rm /etc/httpd/conf.d/ssl.conf
  sudo chmod 644 /etc/httpd/conf.d/misp.ssl.conf
  sudo sed -i '/Listen 80/a Listen 443' /etc/httpd/conf/httpd.conf

  # If a valid SSL certificate is not already created for the server, create a self-signed certificate:
  echo "The Common Name used below will be: ${OPENSSL_CN}"
  # This will take a rather long time, be ready. (13min on a VM, 8GB Ram, 1 core)
  if [[ ! -e "/etc/pki/tls/certs/dhparam.pem" ]]; then
    sudo openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 4096
  fi
  sudo openssl genrsa -des3 -passout pass:xxxx -out /tmp/misp.local.key 4096
  sudo openssl rsa -passin pass:xxxx -in /tmp/misp.local.key -out /etc/pki/tls/private/misp.local.key
  sudo rm /tmp/misp.local.key
  sudo openssl req -new -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" -key /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.csr
  sudo openssl x509 -req -days 365 -in /etc/pki/tls/certs/misp.local.csr -signkey /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt
  sudo ln -s /etc/pki/tls/certs/misp.local.csr /etc/pki/tls/certs/misp-chain.crt
  cat /etc/pki/tls/certs/dhparam.pem |sudo tee -a /etc/pki/tls/certs/misp.local.crt

  sudo systemctl restart httpd.service

  # Since SELinux is enabled, we need to allow httpd to write to certain directories
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/terms
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/tmp
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/cake
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/worker/*.sh
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*.py
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*/*.py
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/lief/build/api/python/lief.so
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Vendor/pear/crypt_gpg/scripts/crypt-gpg-pinentry
  sudo chcon -R -t bin_t $PATH_TO_MISP/venv/bin/*
  find $PATH_TO_MISP/venv -type f -name "*.so*" -or -name "*.so.*" | xargs sudo chcon -t lib_t
  # Only run these if you want to be able to update MISP from the web interface
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.git
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Lib
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/orgs
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/custom
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/mispzmq
}

firewall_RHEL () {
  # Allow httpd to connect to the redis server and php-fpm over tcp/ip
  sudo setsebool -P httpd_can_network_connect on

  # Allow httpd to send emails from php
  sudo setsebool -P httpd_can_sendmail on

  # Enable and start the httpd service
  sudo systemctl enable --now httpd.service

  # Open a hole in the iptables firewall
  sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
  sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
  sudo firewall-cmd --reload
}

# Main function to fix permissions to something sane
permissions_RHEL () {
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  ## ? chown -R root:$WWW_USER $PATH_TO_MISP
  sudo find $PATH_TO_MISP -type d -exec chmod g=rx {} \;
  sudo chmod -R g+r,o= $PATH_TO_MISP
  ## **Note :** For updates through the web interface to work, apache must own the $PATH_TO_MISP folder and its subfolders as shown above, which can lead to security issues. If you do not require updates through the web interface to work, you can use the following more restrictive permissions :
  sudo chmod -R 750 $PATH_TO_MISP
  sudo chmod -R g+xws $PATH_TO_MISP/app/tmp
  sudo chmod -R g+ws $PATH_TO_MISP/app/files
  sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
  sudo chmod -R g+rw $PATH_TO_MISP/venv
  sudo chmod -R g+rw $PATH_TO_MISP/.git
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/terms
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/scripts/tmp
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/orgs
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/custom
}

logRotation_RHEL () {
  # MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
  # To rotate these logs install the supplied logrotate script:

  sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp
  sudo chmod 0640 /etc/logrotate.d/misp

  # Now make logrotate work under SELinux as well
  # Allow logrotate to modify the log files
  sudo semanage fcontext -a -t httpd_sys_rw_content_t "$PATH_TO_MISP(/.*)?"
  sudo semanage fcontext -a -t httpd_log_t "$PATH_TO_MISP/app/tmp/logs(/.*)?"
  sudo chcon -R -t httpd_log_t $PATH_TO_MISP/app/tmp/logs
  # Impact of the following: ?!?!?!!?111
  ##sudo restorecon -R $PATH_TO_MISP

  # Allow logrotate to read /var/www
  sudo checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te
  sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
  sudo semodule -i /tmp/misplogrotate.pp
}

configMISP_RHEL () {
  # There are 4 sample configuration files in $PATH_TO_MISP/app/Config that need to be copied
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php

  echo "<?php
  class DATABASE_CONFIG {
          public \$default = array(
                  'datasource' => 'Database/Mysql',
                  //'datasource' => 'Database/Postgres',
                  'persistent' => false,
                  'host' => '$DBHOST',
                  'login' => '$DBUSER_MISP',
                  'port' => 3306, // MySQL & MariaDB
                  //'port' => 5432, // PostgreSQL
                  'password' => '$DBPASSWORD_MISP',
                  'database' => '$DBNAME',
                  'prefix' => '',
                  'encoding' => 'utf8',
          );
  }" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php

  # Configure the fields in the newly created files:
  # config.php   : baseurl (example: 'baseurl' => 'http://misp',) - don't use "localhost" it causes issues when browsing externally
  # core.php   : Uncomment and set the timezone: `// date_default_timezone_set('UTC');`
  # database.php : login, port, password, database
  # DATABASE_CONFIG has to be filled
  # With the default values provided in section 6, this would look like:
  # class DATABASE_CONFIG {
  #   public $default = array(
  #       'datasource' => 'Database/Mysql',
  #       'persistent' => false,
  #       'host' => 'localhost',
  #       'login' => 'misp', // grant usage on *.* to misp@localhost
  #       'port' => 3306,
  #       'password' => 'XXXXdbpasswordhereXXXXX', // identified by 'XXXXdbpasswordhereXXXXX';
  #       'database' => 'misp', // create database misp;
  #       'prefix' => '',
  #       'encoding' => 'utf8',
  #   );
  #}

  # Important! Change the salt key in $PATH_TO_MISP/app/Config/config.php
  # The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
  # If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
  # delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

  # If you want to be able to change configuration parameters from the webinterface:
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config/config.php
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config/config.php

  # Generate a GPG encryption key.
  cat >/tmp/gen-key-script <<EOF
      %echo Generating a default key
      Key-Type: default
      Key-Length: $GPG_KEY_LENGTH
      Subkey-Type: default
      Name-Real: $GPG_REAL_NAME
      Name-Comment: $GPG_COMMENT
      Name-Email: $GPG_EMAIL_ADDRESS
      Expire-Date: 0
      Passphrase: $GPG_PASSPHRASE
      # Do a commit here, so that we can later print "done"
      %commit
      %echo done
EOF

  sudo gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
  sudo rm -f /tmp/gen-key-script
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/.gnupg
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.gnupg

  # And export the public key to the webroot
  sudo gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee $PATH_TO_MISP/app/webroot/gpg.asc
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/gpg.asc

  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"
}

configWorkersRHEL () {
  echo "[Unit]
  Description=MISP background workers
  After=rh-mariadb102-mariadb.service rh-redis32-redis.service rh-php72-php-fpm.service

  [Service]
  Type=forking
  User=$WWW_USER
  Group=$WWW_USER
  ExecStart=/usr/bin/scl enable rh-php72 rh-redis32 rh-mariadb102 $PATH_TO_MISP/app/Console/worker/start.sh
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service

  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
  sudo systemctl daemon-reload

  sudo systemctl enable --now misp-workers.service
}

mispmodulesRHEL () {
  # some misp-modules dependencies
  sudo yum install openjpeg-devel gcc-c++ poppler-cpp-devel pkgconfig python-devel redhat-rpm-config -y

  sudo chmod 2777 /usr/local/src
  sudo chown root:users /usr/local/src
  cd /usr/local/src/
  false; while [[ $? -ne 0 ]]; do $SUDO_WWW git clone https://github.com/MISP/misp-modules.git; done
  cd misp-modules
  # pip install
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U -I -r REQUIREMENTS
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U .
  sudo yum install rubygem-rouge rubygem-asciidoctor zbar-devel opencv-devel -y

  echo "[Unit]
  Description=MISP modules
  After=misp-workers.service

  [Service]
  Type=simple
  User=$WWW_USER
  Group=$WWW_USER
  WorkingDirectory=/usr/local/src/misp-modules
  Environment="PATH=/var/www/MISP/venv/bin"
  ExecStart=\"${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s\"
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-modules.service

  sudo systemctl daemon-reload
  # Test misp-modules
  $SUDO_WWW $PATH_TO_MISP/venv/bin/misp-modules -l 127.0.0.1 -s &
  sudo systemctl enable --now misp-modules

  # Enable Enrichment, set better timeouts
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
  # TODO:"Investigate why the next one fails"
  #$SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_btc_steroids_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_ipasn_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_yara_syntax_validator_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_yara_query_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_pdf_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_docx_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_xlsx_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_pptx_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_ods_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_odt_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules, set better timeout
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_services_port" 6666
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_timeout" 300
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_mispjson_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_openiocimport_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_threatanalyzer_import_enabled" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

  # Enable Export modules, set better timeout
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_services_port" 6666
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_timeout" 300
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true
}


# No functions scripts:
## apt-upgrade.sh ##
## postfix.sh ##
## interfaces.sh ##
#
### END AUTOMATED SECTION ###

# This function will generate the main installer.
# It is a helper function for the maintainers of the installer.

colors () {
  # Some colors for easier debug and better UX (not colorblind compatible, PR welcome)
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  LBLUE='\033[1;34m'
  YELLOW='\033[0;33m'
  HIDDEN='\e[8m'
  NC='\033[0m'
}




# Main Install on RHEL function
installMISPRHEL () {

    space
    echo "Proceeding with MISP core installation on RHEL ${dist_version}"
    space
    
    

    id -u "${MISP_USER}" > /dev/null
    if [[ $? -eq 1 ]]; then
      debug "Creating MISP user"
      sudo useradd -r "${MISP_USER}"
    fi 
    
    centosEPEL

    echo "The following DB Passwords were generated..."
    echo "Admin (${DBUSER_ADMIN}) DB Password: ${DBPASSWORD_ADMIN}"
    echo "User  (${DBUSER_MISP}) DB Password: ${DBPASSWORD_MISP}"

    debug "Installing System Dependencies"
    yumInstallCoreDeps

    debug "Enabling Haveged for additional entropy"
    sudo yum install haveged -y
    sudo systemctl enable --now haveged.service

    debug "Installing MISP code"
    installCoreRHEL

    debug "Install Cake PHP"
    installCake_RHEL

    debug "Setting File permissions"
    permissions_RHEL

    debug "Preparing Database"
    prepareDB_RHEL

    debug "Configuring Apache"
    apacheConfig_RHEL

    debug "Setting up firewall"
    firewall_RHEL

    debug "Enabling log rotation"
    logRotation_RHEL

    debug "Configuring MISP"
    configMISP_RHEL

    debug "Setting up background workers"
    configWorkersRHEL

    debug "Optimizing Cake Installation"
    coreCAKE

    debug "Updating tables"
    updateGOWNT

    echo "Core Intallation finished, check on port 443 to see the Web UI"

    space
    echo "Installing MISP Modules"
    space

    mispmodulesRHEL

    echo "MISP modules installation finished."

}
# End installMISPRHEL ()

## End Function Section ##

colors
debug "Checking Linux distribution and flavour..."
checkFlavour
space
debug "Setting MISP variables"
source misp.variables.sh

# If RHEL/CentOS is detected, run appropriate script
if [[ "${FLAVOUR}" == "rhel" ]] || [[ "${FLAVOUR}" == "centos" ]]; then
  installMISPRHEL
  echo "Installation done !"
  exit
fi
