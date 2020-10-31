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

# Main MISP Dashboard install function
mispDashboard () {
  echo "Install misp-dashboard"
  # Install pyzmq to main MISP venv
  echo "Installing PyZMQ"
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
                   htop \
                   httpd24 \
                   mod_ssl \
                   rh-redis32 \
                   rh-mariadb101 \
                   libxslt-devel zlib-devel ssdeep-devel -y

  # Enable and start redis
  sudo systemctl enable --now rh-redis32-redis.service

  # Install PHP 7.2 from SCL, see https://www.softwarecollections.org/en/scls/rhscl/rh-php72/
  sudo yum install rh-php72 rh-php72-php-fpm rh-php72-php-devel \
                   rh-php72-php-mysqlnd \
                   rh-php72-php-mbstring \
                   rh-php72-php-xml \
                   rh-php72-php-intl \
                   rh-php72-php-bcmath \
                   rh-php72-php-opcache \
                   rh-php72-php-gd -y

  # Python 3.6 is now available in RHEL 7.7 base
  sudo yum install python3 python3-pip python3-devel -y
  
  # Install Python 3.6 from SCL, see
  # https://www.softwarecollections.org/en/scls/rhscl/rh-python36/
  #sudo yum install rh-python36 -y

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
  #$SUDO_WWW $RUN_PYTHON -- virtualenv -p python3 $PATH_TO_MISP/venv
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

  # Gtcaca & Faup needs manual compilation
  sudo yum install gcc-c++ libcaca-devel -y
  cd /tmp
  #$SUDO_CMD git clone https://github.com/MISP/misp-modules.git;
  $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca
  $SUDO_CMD git clone https://github.com/stricaud/faup.git faup
  #sudo chown -R ${$WWW_USER}:${$WWW_USER} faup gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} gtcaca faup
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # Enable dependencies detection in the diagnostics page
  # This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
  # The LD_LIBRARY_PATH setting is needed for rh-git218 to work
  echo "env[PATH] = /opt/rh/rh-git218/root/usr/bin:/opt/rh/rh-redis32/root/usr/bin:/opt/rh/rh-php72/root/usr/bin:/usr/local/bin:/usr/bin:/bin" |sudo tee -a /etc/opt/rh/rh-php72/php-fpm.d/www.conf
  echo "env[LD_LIBRARY_PATH] = /opt/rh/httpd24/root/usr/lib64" |sudo tee -a /etc/opt/rh/rh-php72/php-fpm.d/www.conf
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
  sudo chmod 644 /etc/opt/rh/rh-php72/php.d/99-redis.ini
  #echo "extension=redis.so" |sudo tee /etc/opt/rh/rh-php72/php-fpm.d/redis.ini
  #sudo ln -s /etc/opt/rh/rh-php72/php-fpm.d/redis.ini /etc/opt/rh/rh-php72/php.d/99-redis.ini

  sudo ln -s /usr/lib64/libfuzzy.so /usr/lib/libfuzzy.so
  sudo scl enable rh-php72 'pecl install ssdeep'
  echo "extension=ssdeep.so" |sudo tee /etc/opt/rh/rh-php72/php.d/99-ssdeep.ini
  sudo chmod 644 /etc/opt/rh/rh-php72/php.d/99-ssdeep.ini

  #echo "extension=ssdeep.so" |sudo tee /etc/opt/rh/rh-php72/php-fpm.d/ssdeep.ini
  #sudo ln -s /etc/opt/rh/rh-php72/php-fpm.d/ssdeep.ini /etc/opt/rh/rh-php72/php.d/99-ssdeep.ini

  # Install gnupg extension
  sudo yum install gpgme-devel -y
  
  sudo scl enable rh-php72 'pecl install gnupg'
  echo "extension=gnupg.so" |sudo tee /etc/opt/rh/rh-php72/php.d/99-gnupg.ini
  sudo chmod 644 /etc/opt/rh/rh-php72/php.d/99-gnupg.ini
  #echo "extension=gnupg.so" |sudo tee /etc/opt/rh/rh-php72/php-fpm.d/gnupg.ini
  #sudo ln -s /etc/opt/rh/rh-php72/php-fpm.d/gnupg.ini /etc/opt/rh/rh-php72/php.d/99-gnupg.ini

  # If you have not yet set a timezone in php.ini
  echo 'date.timezone = "Asia/Jakarta"' |sudo tee /etc/opt/rh/rh-php72/php.d/99-timezone.ini
  sudo chmod 644 /etc/opt/rh/rh-php72/php.d/99-timezone.ini
  #sudo ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php72/php.d/99-timezone.ini
  sudo systemctl restart rh-php72-php-fpm.service

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
  RUN_MYSQL="/usr/bin/scl enable rh-mariadb101"
  # Enable, start and secure your mysql database server
  sudo systemctl enable --now rh-mariadb101-mariadb.service
  echo [mysqld] |sudo tee /etc/opt/rh/rh-mariadb101/my.cnf.d/bind-address.cnf
  echo bind-address=127.0.0.1 |sudo tee -a /etc/opt/rh/rh-mariadb101/my.cnf.d/bind-address.cnf
   
  echo [mysqld] |sudo tee /etc/opt/rh/rh-mariadb101/my.cnf.d/character-set.cnf
  echo character-set-server=utf8 |sudo tee -a /etc/opt/rh/rh-mariadb101/my.cnf.d/character-set.cnf
  chmod 644 /etc/opt/rh/rh-mariadb101/my.cnf.d/character-set.cnf

  sudo systemctl restart rh-mariadb101-mariadb

  sudo yum install expect -y

  ## The following needs some thoughts about scl enable foo
  #if [[ ! -e /var/opt/rh/rh-mariadb101/lib/mysql/misp/users.ibd ]]; then

  # We ask interactively your password if not run as root
  pw=""
  if [[ "$EUID" -ne 0 ]]; then
    read -s -p "Enter sudo password: " pw
  fi

  expect -f - <<-EOF
    set timeout 10

    spawn sudo scl enable rh-mariadb101 mysql_secure_installation
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

  sudo systemctl restart rh-mariadb101-mariadb

  scl enable rh-mariadb101 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e 'CREATE DATABASE $DBNAME;'"
  scl enable rh-mariadb101 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e \"GRANT USAGE on *.* to $DBUSER_MISP@localhost IDENTIFIED by '$DBPASSWORD_MISP';\""
  scl enable rh-mariadb101 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e \"GRANT ALL PRIVILEGES on $DBNAME.* to '$DBUSER_MISP'@'localhost';\""
  scl enable rh-mariadb101 "mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e 'FLUSH PRIVILEGES;'"

  $SUDO_WWW cat $PATH_TO_MISP/INSTALL/MYSQL.sql | sudo scl enable rh-mariadb101 "mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME"
}

apacheConfig_RHEL () {
  # Now configure your apache server with the DocumentRoot $PATH_TO_MISP/app/webroot/
  # A sample vhost can be found in $PATH_TO_MISP/INSTALL/apache.misp.centos7

  #sudo cp $PATH_TO_MISP/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf
  sudo cp $PATH_TO_MISP/INSTALL/apache.misp.centos7 /etc/httpd/conf.d/misp.conf
  
  #sudo sed -i "s/SetHandler/\#SetHandler/g" /etc/httpd/conf.d/misp.ssl.conf
  #sudo rm /etc/httpd/conf.d/ssl.conf
  #sudo chmod 644 /etc/httpd/conf.d/misp.ssl.conf
  sudo chmod 644 /etc/httpd/conf.d/misp.conf
  #sudo sed -i '/Listen 80/a Listen 443' /etc/httpd/conf/httpd.conf

  # If a valid SSL certificate is not already created for the server, create a self-signed certificate:
  #echo "The Common Name used below will be: ${OPENSSL_CN}"
  
  # This will take a rather long time, be ready. (13min on a VM, 8GB Ram, 1 core)
  #if [[ ! -e "/etc/pki/tls/certs/dhparam.pem" ]]; then
  #  sudo openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 2048
  #fi
  #sudo openssl genrsa -des3 -passout pass:xxxx -out /tmp/misp.local.key 2048
  #sudo openssl rsa -passin pass:xxxx -in /tmp/misp.local.key -out /etc/pki/tls/private/misp.local.key
  #sudo rm /tmp/misp.local.key
  #sudo openssl req -new -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" -key /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.csr
  #sudo openssl x509 -req -days 365 -in /etc/pki/tls/certs/misp.local.csr -signkey /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt
  #sudo ln -s /etc/pki/tls/certs/misp.local.csr /etc/pki/tls/certs/misp-chain.crt
  #cat /etc/pki/tls/certs/dhparam.pem |sudo tee -a /etc/pki/tls/certs/misp.local.crt

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
  After=rh-mariadb101-mariadb.service rh-redis32-redis.service rh-php72-php-fpm.service

  [Service]
  Type=forking
  User=$WWW_USER
  Group=$WWW_USER
  ExecStart=/usr/bin/scl enable rh-php72 rh-redis32 rh-mariadb101 $PATH_TO_MISP/app/Console/worker/start.sh
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service

  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
  sudo systemctl daemon-reload

  sudo systemctl enable --now misp-workers.service
}

coreCAKERHEL () {
  echo "Running core Cake commands to set sane defaults for ${LBLUE}MISP${NC}"

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
updateGOWNTRHEL () {
  # AUTH_KEY Place holder in case we need to **curl** somehing in the future
  # 
  $SUDO_WWW $RUN_MYSQL -- mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1 > /tmp/auth.key
  AUTH_KEY=$(cat /tmp/auth.key)
  rm /tmp/auth.key

  echo "Updating Galaxies, ObjectTemplates, Warninglists, Noticelists and Templates"
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
  sudo yum install rh-ruby24 rubygem-rouge rubygem-asciidoctor zbar-devel opencv-devel -y

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
  #ExecStart=/usr/bin/scl enable rh-python36 rh-ruby24 '/var/www/MISP/venv/bin/misp-modules –l 127.0.0.1 –s'
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

# Final function to let the user know what happened
theEndRHEL () {
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
}
## End Function Section Nothing allowed in .md after this line ##

### END AUTOMATED SECTION ###

# This function will generate the main installer.
# It is a helper function for the maintainers of the installer.
# Main Install on RHEL function
installMISPRHEL () {
    echo "Proceeding with MISP core installation on RHEL ${dist_version}"
    space
    id -u "${MISP_USER}" > /dev/null
    echo "Creating MISP user"
    sudo useradd "${MISP_USER}"
    
    echo "Installing Centos EPEL..."
    centosEPEL

    echo "Installing System Dependencies"
    yumInstallCoreDeps

    echo "Enabling Haveged for additional entropy"
    sudo yum install haveged -y
    sudo systemctl enable --now haveged.service

    echo "Installing MISP code"
    installCoreRHEL

    echo "Install Cake PHP"
    installCake_RHEL

    echo "Setting File permissions"
    permissions_RHEL

    echo "Preparing Database"
    prepareDB_RHEL

    echo "Configuring Apache"
    apacheConfig_RHEL

    echo "Setting up firewall"
    firewall_RHEL

    echo "Enabling log rotation"
    logRotation_RHEL

    echo "Configuring MISP"
    configMISP_RHEL

    echo "Setting up background workers"
    configWorkersRHEL

    echo "Optimizing Cake Installation"
    coreCAKERHEL

    echo "Updating tables"
    updateGOWNTRHEL
    
#    echo "Installing MISP Modules"
#    mispmodulesRHEL

    space
    theEndRHEL
    echo "MISP Intallation finished, check on port 80/443 to see the Web UI"
}
# End installMISPRHEL ()
## End Function Section ##

echo "Checking Linux distribution and flavour..."
checkFlavour
echo "Setting MISP variables"
source misp.variables.sh

# If RHEL/CentOS is detected, run appropriate script
if [[ "${FLAVOUR}" == "rhel" ]] || [[ "${FLAVOUR}" == "centos" ]]; then
  echo "Flavour="${FLAVOUR}
  space 
  installMISPRHEL
  echo "Installation done !"
  exit
fi