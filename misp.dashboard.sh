#!/usr/bin/env bash

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

# <snippet-begin 4_misp-dashboardRHEL.sh>
# Main MISP Dashboard install function
mispDashboardRHEL () {
  sudo yum install wget screen -y
  sudo mkdir /var/www/misp-dashboard
  sudo chown -R $WWW_USER:$WWW_USER /var/www/misp-dashboard
  cd /var/www/misp-dashboard
  $SUDO_WWW git clone https://github.com/MISP/misp-dashboard.git /var/www/misp-dashboard
  sudo sed -i -E 's/sudo apt/#sudo apt/' install_dependencies.sh
  sudo sed -i -E 's/virtualenv -p python3 DASHENV/\/usr\/bin\/scl enable rh-python36 \"virtualenv -p python3 DASHENV\"/' install_dependencies.sh
  sudo -H /var/www/misp-dashboard/install_dependencies.sh
  sudo sed -i "s/^host\ =\ localhost/host\ =\ 0.0.0.0/g" /var/www/misp-dashboard/config/config.cfg
  sudo sed -i '/Listen 80/a Listen 0.0.0.0:8001' /etc/httpd/conf/httpd.conf
  sudo yum install rh-python36-mod_wsgi -y
  sudo cp /opt/rh/httpd24/root/usr/lib64/httpd/modules/mod_rh-python36-wsgi.so /etc/httpd/modules/
  sudo cp /opt/rh/httpd24/root/etc/httpd/conf.modules.d/10-rh-python36-wsgi.conf /etc/httpd/conf.modules.d/

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
      ErrorLog /var/log/httpd/misp-dashboard.local_error.log
      CustomLog /var/log/httpd/misp-dashboard.local_access.log combined
      ServerSignature Off
  </VirtualHost>" | sudo tee /etc/httpd/conf.d/misp-dashboard.conf

  sudo semanage port -a -t http_port_t -p tcp 8001
  sudo systemctl restart httpd.service 
  sudo firewall-cmd --zone=public --add-port=8001/tcp --permanent
  sudo firewall-cmd --reload

  # Add misp-dashboard to rc.local to start on boot.
  sudo sed -i -e '$i \sudo -u apache bash /var/www/misp-dashboard/start_all.sh > /tmp/misp-dashboard_rc.local.log\n' /etc/rc.local

  # Enable ZeroMQ for misp-dashboard
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" true
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_port" 50000
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false
  $SUDO_WWW $RUN_PHP -- $CAKE Admin setSetting "Plugin.ZeroMQ_audit_notifications_enable" false
}
# <snippet-end 4_misp-dashboardRHEL.sh>

echo "Checking Linux distribution and flavour..."
checkFlavour

echo "Setting MISP Dashboard variables"
WWW_USER="apache"
SUDO_WWW="sudo -H -u $WWW_USER"
RUN_PYTHON='/usr/bin/scl enable rh-python36 '
RUN_MYSQL='/usr/bin/scl enable rh-mariadb101 '
RUN_PHP='/usr/bin/scl enable rh-php72 '
PATH_TO_MISP='/var/www/MISP'
CAKE="$PATH_TO_MISP/app/Console/cake"

# If RHEL/CentOS is detected, run appropriate script
if [[ "${FLAVOUR}" == "rhel" ]] || [[ "${FLAVOUR}" == "centos" ]]; then
  echo "Proceeding with MISP Dashboard installation on CentOS ${FLAVOUR} - ${dist_version}" 
  mispDashboardRHEL
  echo "MISP Dashboard intallation finished!!!....."
  exit
fi