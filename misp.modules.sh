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

mispmodulesRHEL () {
  # some misp-modules dependencies
  sudo yum install openjpeg-devel gcc-c++ poppler-cpp-devel pkgconfig python-devel redhat-rpm-config -y

  sudo chmod 2777 /usr/local/src
  sudo chown root:users /usr/local/src
  cd /usr/local/src/
  false; while [[ $? -ne 0 ]]; do $SUDO_WWW git clone https://github.com/MISP/misp-modules.git; done
  cd misp-modules
  # pip install
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install censys pyfaup
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
  echo "Testing MISP Modules!!!....."
  $SUDO_WWW $PATH_TO_MISP/venv/bin/misp-modules -l 127.0.0.1 -s &
  
  echo "Enable MISP Modules....."
  sudo systemctl enable misp-modules.service
  sudo systemctl start misp-modules.service

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

  sudo systemctl restart httpd.service
  sudo systemctl restart rh-php72-php-fpm.service
  
}

echo "Checking Linux distribution and flavour..."
checkFlavour

echo "Setting MISP variables"
WWW_USER="apache"
SUDO_WWW="sudo -H -u $WWW_USER"
RUN_PYTHON='/usr/bin/scl enable rh-python36 '
RUN_MYSQL='/usr/bin/scl enable rh-mariadb101 '
RUN_PHP='/usr/bin/scl enable rh-php72 '
PATH_TO_MISP='/var/www/MISP'
CAKE="$PATH_TO_MISP/app/Console/cake"

# If RHEL/CentOS is detected, run appropriate script
if [[ "${FLAVOUR}" == "rhel" ]] || [[ "${FLAVOUR}" == "centos" ]]; then
  echo "Proceeding with MISP Modules installation on CentOS ${FLAVOUR} - ${dist_version}" 
  mispmodulesRHEL
  echo "MISP Modules intallation finished!!!....."
  exit
fi