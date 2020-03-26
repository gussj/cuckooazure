#!/bin/bash
su cuckoo -c '. ~/cuckoo/bin/activate && vmcloak-vboxnet0 && supervisord -c /home/cuckoo/.cuckoo/supervisord.conf'
exit
