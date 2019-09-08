#!/bin/bash
CURRENTUSER=$(whoami)

if [ $# -eq 0 ]
   then
    echo ""
    echo "            Cuckoo Sandbox Headless"
    echo "-----------------------------------------------------"
    echo "COMMANDS:"
    echo "prereq      = This will install all the pre-req software for running Cukoo"
    echo "boombox     = This only installs boombox for headless server"
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
	sudo aa-disable /usr/sbin/tcpdump
	sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
	cd
	mkdir /home/$CURRENTUSER/csand
	cd /home/$CURRENTUSER/csand
	mkdir files
	cd files
	wget https://download.virtualbox.org/virtualbox/6.0.12/Oracle_VM_VirtualBox_Extension_Pack-6.0.12.vbox-extpack
	sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-5.1.0-108711.vbox-extpack
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
