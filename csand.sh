#!/bin/bash

CURRENTUSER="$(whoami)"
export CURRENTUSER

if [ "$#" -gt 2 ]
then
    print_usage
exit 1
fi
	
print_usage() {
  echo "Usage:"
  echo "./csand.sh prereq"
  echo "./csand.sh boombox"
  echo "./csand.sh vmcloack"
  echo "Only one argument can be used at a time."
  exit 0
}

KNOWN_DISTRIBUTION="(RedHat|CentOS|Debian|Ubuntu|openSUSE|Amazon|SUSE)"
DISTRIBUTION=$(lsb_release -d 2>/dev/null | grep -Eo $KNOWN_DISTRIBUTION  || grep -Eo $KNOWN_DISTRIBUTION /etc/issue 2>/dev/null || grep -Eo $KNOWN_DISTRIBUTION /etc/Eos-release 2>/dev/null || grep -m1 -Eo $KNOWN_DISTRIBUTION /etc/os-release 2>/dev/null || uname -s)

if [ "$DISTRIBUTION" = "Darwin" ]
then
	echo "OS not supported."
	exit 0
	elif [ -f /etc/debian_version -o "$DISTRIBUTION" == "Debian" -o "$DISTRIBUTION" == "Ubuntu" ]; then
	OS="Debian"
	export OS
	elif [ -f /etc/redhat-release -o "$DISTRIBUTION" == "RedHat" -o "$DISTRIBUTION" == "CentOS" -o "$DISTRIBUTION" == "Amazon" ]; then
	echo "OS not supported."
	exit 0
	elif [ -f /etc/SuSE-release -o "$DISTRIBUTION" == "SUSE" -o "$DISTRIBUTION" == "openSUSE" ]; then
    echo "OS not supported."
	exit 0
fi


if [ $# -eq 0 ] && [ $OS == "Debian" ]
   then
    echo ""
    echo "         Cuckoo Sandbox Headless for Azure        "
    echo "-----------------------------------------------------"
    echo "COMMANDS:"
    echo "prereq      = This will install all the pre-req software for running Cukoo (this is a required step for first time users)"
    echo "boombox     = This only installs boombox and cuckoo for headless server"
	echo "vmcloack    = This will install vmcloack and cuckoo for headless server"
    echo ""
    else
    echo "System not supported"
fi
 
if [ "$1" = "prereq" ]
   then
	# determine if we need sudo
	if [ "$(echo "$UID")" = "0" ]; then
	  sudo_cmd=''
	else
	  sudo_cmd='sudo'
	fi
	echo "Installing pre-reqs"
	#$(sudo add-apt-repository universe)
	$sudo_cmd add-apt-repository universe
	$sudo_cmd add-apt-repository multiverse
	$sudo_cmd echo "deb https://download.virtualbox.org/virtualbox/debian disco contrib" | sudo tee -a /etc/apt/sources.list
	$sudo_cmd wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
	$sudo_cmd wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
	$sudo_cmd apt-get update
	$sudo_cmd apt-get upgrade --allow-downgrades --allow-remove-essential --allow-change-held-packages
	$sudo_cmd apt-get install iptables-persistent git libffi-dev libjpeg8-dev zlib1g-dev genisoimage supervisor uwsgi uwsgi-plugin-python nginx build-essential unzip python-django python python-dev python-pip python-pil python-sqlalchemy python-bson python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-libvirt python-bottle python-pefile python-chardet tcpdump apparmor-utils libjpeg-dev python-virtualenv python3-virtualenv virtualenv swig libpq-dev autoconf libtool libjansson-dev libmagic-dev libssl-dev virtualbox-5.2 -y
	$sudo_cmd adduser --disabled-password --gecos "" cuckoo
	$sudo_cmd groupadd pcap
	$sudo_cmd usermod -a -G pcap cuckoo
	$sudo_cmd chgrp pcap /usr/sbin/tcpdump
	$sudo_cmd setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
	cd
	$sudo_cmd mkdir /home/"$CURRENTUSER"/csand
	cd /home/"$CURRENTUSER"/csand
	$sudo_cmd mkdir files
	cd files
	$sudo_cmd wget https://download.virtualbox.org/virtualbox/6.0.12/Oracle_VM_VirtualBox_Extension_Pack-6.0.12.vbox-extpack
	$sudo_cmd VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-6.0.12.vbox-extpack --accept-license=56be48f923303c8cababb0bb4c478284b688ed23f16d775d729b89a2e8e5f9eb
	$sudo_cmd usermod -a -G vboxusers cuckoo
	$sudo_cmd wget https://github.com/VirusTotal/yara/archive/v3.10.0.tar.gz -O yara-3.10.0.tar.gz
	$sudo_cmd tar -zxf yara-3.10.0.tar.gz
	cd yara-3.10.0
	$sudo_cmd ./bootstrap.sh
	$sudo_cmd ./configure -with-crypto -enable-cuckoo -enable-magic
	$sudo_cmd make
	$sudo_cmd make install
	$sudo_cmd ln -s /usr/local/lib/libyara.so.3 /usr/lib/libyara.so.3
	$sudo_cmd wget https://github.com/VirusTotal/yara-python/archive/v3.10.0.tar.gz -O yara-python.tar.gz
	$sudo_cmd tar -zxf yara-python.tar.gz
	cd yara-python-3.10.0
	$sudo_cmd python setup.py build
	$sudo_cmd python setup.py install
	cd /home/"$CURRENTUSER"/csand/files/
	$sudo_cmd wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz -O ssdeep-2.14.1.tar.gz
	$sudo_cmd tar -zxf ssdeep-2.14.1.tar.gz
	cd ssdeep-2.14.1
	$sudo_cmd ./configure
	$sudo_cmd make
	$sudo_cmd make install
	pip install pydeep
	pip install openpyxl
	pip install ujson
	pip install pycrypto
	pip install distorm3
	pip install pytz
	pip install jsonschema
	cd /home/"$CURRENTUSER"/csand/files/
	$sudo_cmd git clone https://github.com/volatilityfoundation/volatility.git
	cd volatility
	$sudo_cmd python setup.py build
	$sudo_cmd python setup.py install
	cd /home/"$CURRENTUSER"/csand/files/
	$sudo_cmd wget https://releases.hashicorp.com/packer/1.4.3/packer_1.4.3_linux_amd64.zip
	$sudo_cmd unzip packer_1.4.3_linux_amd64.zip
	$sudo_cmd mv packer /usr/local/bin
	$sudo_cmd wget https://releases.hashicorp.com/vagrant/2.2.5/vagrant_2.2.5_x86_64.deb
	$sudo_cmd dpkg -i vagrant_2.2.5_x86_64.deb
    echo "Finish installing pre-reqs"
exit
fi

if [ "$1" = "boombox" ]
   then
	# determine if we need sudo
	if [ "$(echo "$UID")" = "0" ]; then
	  sudo_cmd=''
	else
	  sudo_cmd='sudo'
	fi
	DIR="/home/$CURRENTUSER/csand/"
	if [ -d "$DIR" ]; then
	echo "Initiating Boombox Installation"
	cd /home/"$CURRENTUSER"/csand/
	wget https://github.com/gussj/BoomBox/archive/master.zip -O boombox.tar.gz
	tar -zxf boombox.tar.gz
	cd BoomBox-master/
	./build.sh virtualbox
	else
	mkdir /home/"$CURRENTUSER"/csand
	cd /home/"$CURRENTUSER"/csand/
	wget https://github.com/gussj/BoomBox/archive/master.zip -O boombox.tar.gz
	tar -zxf boombox.tar.gz
	cd BoomBox-master/
	./build.sh virtualbox
	echo "Finish Boombox Installation"
	fi
exit
fi

if [ "$1" = "vmcloack" ]
   then
	# determine if we need sudo
	if [ "$(echo "$UID")" = "0" ]; then
	  sudo_cmd=''
	else
	  sudo_cmd='sudo'
	fi
	DIR="/home/$CURRENTUSER/csand/"
	if [ -d "$DIR" ]; then
	echo "Initiating VMCloak and Cuckoo Installation"
	cd /home/"$CURRENTUSER"/csand/
	$sudo_cmd apt-get update
	$sudo_cmd apt-get -y install python virtualenv python-pip python-dev build-essential
	$sudo_cmd apt-get -y install postgresql postgresql-contrib
	$sudo_cmd wget https://cuckoo.sh/win7ultimate.iso
	$sudo_cmd mkdir /mnt/win7
	$sudo_cmd mount -o ro,loop win7ultimate.iso /mnt/win7
	$sudo_cmd apt-get -y install build-essential libssl-dev libffi-dev python-dev genisoimage mongodb supervisord
	$sudo_cmd apt-get -y install zlib1g-dev libjpeg-dev
	$sudo_cmd apt-get -y install python-pip python-virtualenv python-setuptools swig
	pip install --upgrade pip
	pip install pillow
	pip install --upgrade pillow
	sudo -u postgres psql
	CREATE DATABASE cuckoo;
	CREATE USER cuckoo WITH ENCRYPTED PASSWORD 'password';
	GRANT ALL PRIVILEGES ON DATABASE cuckoo TO cuckoo;
	\q
	#edit conf/cuckoo connection = postgresql://cuckoo:password@localhost/cuckoo
	$sudo_cmd su cuckoo
	virtualenv ~/cuckoo
	. ~/cuckoo/bin/activate
	pip install -U cuckoo vmcloak uwsgi psycopg2
	#execute this on computer turns on
	vmcloak-vboxnet0
	vmcloak init --verbose --win7x64 win7x64base --cpus 2 --ramsize 2048
	vmcloak clone win7x64base win7x64cuckoo
	vmcloak install win7x64cuckoo adobepdf pillow dotnet java flash vcredist vcredist.version=2015u3 wallpaper ie11
	vmcloak snapshot --count 4 win7x64cuckoo_ 192.168.56.101
	# this should be moved to root user
	$sudo_cmd sysctl -w net.ipv4.conf.vboxnet0.forwarding=1
	$sudo_cmd sysctl -w net.ipv4.conf.eth0.forwarding=1
	$sudo_cmd iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
	$sudo_cmd iptables -P FORWARD DROP
	$sudo_cmd iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	$sudo_cmd iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	# end of move
	cuckoo init
	# need to modify the cuckoo files with no machines. /conf/virtualbox.conf machines =
	while read -r vm ip; do cuckoo machine --add $vm $ip; done < <(vmcloak list vms)
	cuckoo community --force
	cuckoo web --uwsgi > /home/cuckoo/cuckoo-web.ini
	#need to go to root context
	sudo cp /home/cuckoo/cuckoo-web.ini /etc/uwsgi/apps-available/cuckoo-web.ini
	sudo ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/cuckoo-web.ini
	sudo adduser www-data cuckoo
	sudo systemctl restart uwsgi
	#stop root context
	cuckoo web --nginx > /home/cuckoo/cuckoo-web.conf
	#switch root content
	sudo cp /home/cuckoo/cuckoo-web.conf /etc/nginx/sites-available/cuckoo-web.conf
	sudo ln -s /etc/nginx/sites-available/cuckoo-web.conf /etc/nginx/sites-enabled/cuckoo-web.conf
	sudo systemctl restart nginx
	#exit root context
	cuckoo api --uwsgi > /home/cuckoo/cuckoo-api.ini
	#need to go to root context
	sudo cp /home/cuckoo/cuckoo-api.ini /etc/uwsgi/apps-available/cuckoo-api.ini
	sudo ln -s /etc/uwsgi/apps-available/cuckoo-api.ini /etc/uwsgi/apps-enabled/cuckoo-api.ini
	sudo systemctl restart uwsgi
	#stop root context
	cuckoo api --nginx > /home/cuckoo/cuckoo-api.conf
	#switch root content
	sudo cp /home/cuckoo/cuckoo-api.conf /etc/nginx/sites-available/cuckoo-api.conf
	sudo ln -s /etc/nginx/sites-available/cuckoo-api.conf /etc/nginx/sites-enabled/cuckoo-api.conf
	sudo systemctl restart nginx
	#exit root context
	supervisord -c /home/cuckoo/.cuckoo/supervisord.conf
	echo "Finish VMCloack and Cuckoo Installation. You can use (supervisorctl start cuckoo) to start cuckoo in the background. or cuckoo --debug"
	#need to enable virustotal in the config processing file
	else
	mkdir /home/"$CURRENTUSER"/csand
	cd /home/"$CURRENTUSER"/csand/
	$sudo_cmd apt-get update
	$sudo_cmd apt-get -y install python virtualenv python-pip python-dev build-essential
	$sudo_cmd apt-get -y install postgresql postgresql-contrib
	$sudo_cmd wget https://cuckoo.sh/win7ultimate.iso
	$sudo_cmd mkdir /mnt/win7
	$sudo_cmd mount -o ro,loop win7ultimate.iso /mnt/win7
	$sudo_cmd apt-get -y install build-essential libssl-dev libffi-dev python-dev genisoimage mongodb supervisord
	$sudo_cmd apt-get -y install zlib1g-dev libjpeg-dev
	$sudo_cmd apt-get -y install python-pip python-virtualenv python-setuptools swig
	pip install --upgrade pip
	pip install pillow
	pip install --upgrade pillow
	$sudo_cmd su cuckoo
	virtualenv ~/cuckoo
	. ~/cuckoo/bin/activate
	pip install -U cuckoo
	pip install git+https://github.com/gussj/vmcloak.git
	vmcloak-vboxnet0
	vmcloak init --verbose --win7x64 win7x64base --cpus 2 --ramsize 2048
	vmcloak clone win7x64base win7x64cuckoo
	vmcloak install win7x64cuckoo adobepdf pillow dotnet java flash vcredist vcredist.version=2015u3 wallpaper ie11
	vmcloak snapshot --count 4 win7x64cuckoo_ 192.168.56.101
	$sudo_cmd sysctl -w net.ipv4.conf.vboxnet0.forwarding=1
	$sudo_cmd sysctl -w net.ipv4.conf.eth0.forwarding=1
	$sudo_cmd iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
	$sudo_cmd iptables -P FORWARD DROP
	$sudo_cmd iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	$sudo_cmd iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	cuckoo init
	cuckoo web --host 127.0.0.1 --port 8080
	supervisord -c /home/cuckoo/.cuckoo/supervisord.conf
	echo "Finish VMCloack and Cuckoo Installation. You can use (supervisorctl start cuckoo) to start cuckoo in the background."
	fi
exit
fi
