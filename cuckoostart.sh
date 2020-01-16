#!/bin/bash
sudo su cuckoo
. ~/cuckoo/bin/activate
vmcloak-vboxnet0
supervisord -c /home/cuckoo/.cuckoo/supervisord.conf