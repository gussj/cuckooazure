#!/bin/bash
CURRENTUSER=$(whoami)

if [ $# -eq 0 ]
   then
    echo ""
    echo "            Cuckoo Sandbox Headless"
    echo "-----------------------------------------------------"
    echo "COMMANDS:"
    echo "prereq      = This will install all the pre-req software for running Cukoo (this is a required step for first time users)"
    echo "boombox     = This only installs boombox and cuckoo for headless server"
	echo "vmcloack    = This will install vmcloack and cuckoo for headless server"
    echo ""
   exit
 fi
 
if [ $1 = "prereq" ]
   then
	echo "Installing pre-reqs"
	sudo add-apt-repository universe
	sudo add-apt-repository multiverse
	sudo echo "deb https://download.virtualbox.org/virtualbox/debian disco contrib" | sudo tee -a /etc/apt/sources.list
	wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
	wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
	sudo apt-get update --qq
	sudo apt-get upgrade --force-yes
	sudo apt-get install git libffi-dev build-essential unzip python-django python python-dev python-pip python-pil python-sqlalchemy python-bson python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-libvirt python-bottle python-pefile python-chardet tcpdump apparmor-utils libjpeg-dev python-virtualenv python3-virtualenv virtualenv swig libpq-dev autoconf libtool libjansson-dev libmagic-dev libssl-dev virtualbox-6.0 -y
	sudo adduser --disabled-password --gecos "" cuckoo
	sudo groupadd pcap
	sudo usermod -a -G pcap cuckoo
	sudo chgrp pcap /usr/sbin/tcpdump
	sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
	cd
	mkdir /home/$CURRENTUSER/csand
	cd /home/$CURRENTUSER/csand
	mkdir files
	cd files
	wget https://download.virtualbox.org/virtualbox/6.0.12/Oracle_VM_VirtualBox_Extension_Pack-6.0.12.vbox-extpack
	sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-5.1.0-108711.vbox-extpack
	sudo usermod -a -G vboxusers cuckoo
	wget https://github.com/VirusTotal/yara/archive/v3.10.0.tar.gz -O yara-3.10.0.tar.gz
	tar -zxf yara-3.10.0.tar.gz
	cd yara-3.10.0
	./bootstrap.sh
	./configure -with-crypto -enable-cuckoo -enable-magic
	make
	sudo make install
	sudo ln -s /usr/local/lib/libyara.so.3 /usr/lib/libyara.so.3
	wget https://github.com/VirusTotal/yara-python/archive/v3.10.0.tar.gz -O yara-python.tar.gz
	tar -zxf yara-python.tar.gz
	cd yara-python-3.10.0
	python setup.py build
	sudo python setup.py install
	cd /home/$CURRENTUSER/csand/files/
	wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz -O ssdeep-2.14.1.tar.gz
	tar -zxf ssdeep-2.14.1.tar.gz
	cd ssdeep-2.14.1
	./configure
	make
	sudo make install
	pip install pydeep
	pip install openpyxl
	pip install ujson
	pip install pycrypto
	pip install distorm3
	pip install pytz
	pip install jsonschema
	cd /home/$CURRENTUSER/csand/files/
	git clone https://github.com/volatilityfoundation/volatility.git
	cd volatility
	python setup.py build
	sudo python setup.py install
	cd /home/$CURRENTUSER/csand/files/
	wget https://releases.hashicorp.com/packer/1.4.3/packer_1.4.3_linux_amd64.zip
	unzip packer_1.4.3_linux_amd64.zip
	sudo mv packer /usr/local/bin
	wget https://releases.hashicorp.com/vagrant/2.2.5/vagrant_2.2.5_x86_64.deb
	sudo dpkg -i vagrant_2.2.5_x86_64.deb
    echo "Finish installing pre-reqs"
exit
fi

if [ $1 = "boombox" ]
   then
   DIR="/home/$CURRENTUSER/csand/"
	if [ -d "$DIR" ]; then
	echo "Initiating Boombox Installation"
	cd /home/$CURRENTUSER/csand/
	wget https://github.com/gussj/BoomBox/archive/master.zip -O boombox.tar.gz
	tar -zxf boombox.tar.gz
	cd BoomBox-master/
	./build.sh virtualbox
	else
	mkdir /home/$CURRENTUSER/csand
	cd /home/$CURRENTUSER/csand/
	wget https://github.com/gussj/BoomBox/archive/master.zip -O boombox.tar.gz
	tar -zxf boombox.tar.gz
	cd BoomBox-master/
	./build.sh virtualbox
	echo "Finish Boombox Installation"
	fi
exit
fi

if [ $1 = "vmcloack" ]
   then
   DIR="/home/$CURRENTUSER/csand/"
	if [ -d "$DIR" ]; then
	echo "Initiating VMCloak and Cuckoo Installation"
	cd /home/$CURRENTUSER/csand/
	sudo apt-get update
	sudo apt-get -y install python virtualenv python-pip python-dev build-essential
	sudo apt-get -y postgresql postgresql-contrib
	wget https://cuckoo.sh/win7ultimate.iso
	mkdir /mnt/win7
	sudo mount -o ro,loop win7ultimate.iso /mnt/win7
	sudo apt-get -y install build-essential libssl-dev libffi-dev python-dev genisoimage mongodb supervisord
	sudo apt-get -y install zlib1g-dev libjpeg-dev
	sudo apt-get -y install python-pip python-virtualenv python-setuptools swig	
	sudo sysctl -w net.ipv4.conf.vboxnet0.forwarding=1
	sudo sysctl -w net.ipv4.conf.eth0.forwarding=1
	sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
	sudo iptables -P FORWARD DROP
	sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	sudo su cuckoo
	virtualenv ~/cuckoo
	.~/cuckoo/bin/activate
	pip install -U cuckoo vmcloak
	vmcloak-vboxnet0
	vmcloak init --verbose --win7x64 win7x64base --cpus 2 --ramsize 2048
	vmcloak clone win7x64base win7x64cuckoo
	vmcloak install win7x64cuckoo adobepdf pillow dotnet java flash vcredist vcredist.version=2015u3 wallpaper
	vmcloak install win7x64cuckoo ie11
	vmcloak snapshot --count 4 win7x64cuckoo_ 192.168.56.101
	supervisord -c /home/cuckoo/.cuckoo/supervisord.conf
	cuckoo init
	cuckoo web --host 127.0.0.1 --port 8080
	echo "Finish VMCloack and Cuckoo Installation. You can use (supervisorctl start cuckoo) to start cuckoo in the background."
	else
	mkdir /home/$CURRENTUSER/csand
	cd /home/$CURRENTUSER/csand/
	sudo apt-get update
	sudo apt-get -y install python virtualenv python-pip python-dev build-essential
	sudo apt-get -y postgresql postgresql-contrib
	wget https://cuckoo.sh/win7ultimate.iso
	mkdir /mnt/win7
	sudo mount -o ro,loop win7ultimate.iso /mnt/win7
	sudo apt-get -y install build-essential libssl-dev libffi-dev python-dev genisoimage mongodb supervisord
	sudo apt-get -y install zlib1g-dev libjpeg-dev
	sudo apt-get -y install python-pip python-virtualenv python-setuptools swig	
	sudo sysctl -w net.ipv4.conf.vboxnet0.forwarding=1
	sudo sysctl -w net.ipv4.conf.eth0.forwarding=1
	sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
	sudo iptables -P FORWARD DROP
	sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	sudo su cuckoo
	virtualenv ~/cuckoo
	.~/cuckoo/bin/activate
	pip install -U cuckoo vmcloak
	vmcloak-vboxnet0
	vmcloak init --verbose --win7x64 win7x64base --cpus 2 --ramsize 2048
	vmcloak clone win7x64base win7x64cuckoo
	vmcloak install win7x64cuckoo adobepdf pillow dotnet java flash vcredist vcredist.version=2015u3 wallpaper
	vmcloak install win7x64cuckoo ie11
	vmcloak snapshot --count 4 win7x64cuckoo_ 192.168.56.101
	supervisord -c /home/cuckoo/.cuckoo/supervisord.conf
	cuckoo init
	cuckoo web --host 127.0.0.1 --port 8080
	echo "Finish VMCloack and Cuckoo Installation. You can use (supervisorctl start cuckoo) to start cuckoo in the background."
	fi
exit
fi
