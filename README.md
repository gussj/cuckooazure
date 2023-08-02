# Cuckoo Azure
![Build Status](https://img.shields.io/github/forks/gussj/cuckooazure.svg)
![Build Status](https://img.shields.io/github/stars/gussj/cuckooazure.svg)
![License](https://img.shields.io/github/license/gussj/cuckooazure.svg)

# This script is not updated, please before use it modify the script

Cuckoo Sandbox in Azure using Ubuntu Server 19.

This script will install automatically all dependencies and software required  to run Cuckoo Sandbox in Azure.

# Requirements

For running this you are going to need:

 - [ ] Azure Account
 - [ ] Valid Subscription
 - [ ] Know how to open ports in azure
 - [ ] Create Ubuntu Server VM
 - [ ] Time

This is intended for people that actually worked with Cuckoo in many different ways. This script is not for beginners.

## The script
Download the script using git:
```bash
git clone https://github.com/gussj/cuckooazure.git
cd cuckooazure
```
To run the script first give execution permission:

    chmod +x csand.sh
 Then run:

     ./csand.sh

The script will ask for one of this options:
- prereq
- boombox
- vmcloack

The first one will install all the pre requisites for all the VM, Cuckoo and Python, the second will install boombox and Cuckoo and last option will install vmcloack with Cuckoo. Last two options are only recommended for people that already has all the dependencies.

**YOU SHOULD ONLY INSTALL ONE METHOD AT A TIME. IF YOU NEED TO TEST PLEASE USE SNAPSHOTS.**

## Connect VM GUI

Since all the VM are running headless you are going to need to open a RDP port in Azure (Security groups) looking in the result of the scripts.

> Comming soon
