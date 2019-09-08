# Cuckoo Azure
![Build Status](https://img.shields.io/github/forks/gussj/cuckooazure.svg)
![Build Status](https://img.shields.io/github/stars/gussj/cuckooazure.svg)
![License](https://img.shields.io/github/license/gussj/cuckooazure.svg)

Cuckoo Sandbox in Azure using Ubuntu Server 19.

This script will install automatically all dependencies and software required  to run Cuckoo Sandbox in Azure.

# Requirements

For running this you are going to need:

 - [ ] Azure Account
 - [ ] Valid Subscription
 - [ ] Know how to open ports in azure
 - [ ] Create Ubuntu Server VM
 - [ ] Time

## The script

To run the script first give execution permission:

    chmod +x csand.sh
 Then run:

     ./csand.sh

The script will ask for one of this options:
- prereq
- boombox

The first one will install all the pre requisites for all the VM, Cukoo and Python, the second will install boombox only. That option is only recommended for people that already has all the dependencies.

## Connect VM GUI

Since all the VM are running headless you are going to need to open a RDP port in Azure (Security groups) looking in the result of the scripts.

> Comming soon
