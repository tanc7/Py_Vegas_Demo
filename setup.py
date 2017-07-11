import os
import socket
import sys
import operator

# install Tor, Tsocks, and NMap for you

os.system("sudo apt-get update && apt-get install tor tsocks nmap -y")

# git clone the latest repo
os.chdir("/tmp")
os.system("sudo git clone https://raw.githubusercontent.com/tanc7/Py_Vegas_Demo/")

# change to directory and modify file permissions
os.chdir("/tmp/Py_Vegas_Demo")
os.system("sudo chmod 777 nmap_auto_script_demo.py")

# Make a installation directory and copy the modified file over
os.system("mkdir /root/Documents/nmap_auto_script_project/")
os.system("cp -r nmap_auto_script_demo.py /root/Documents/nmap_auto_script_project/nmap_auto_script_demo.py")

# automatically start the copy
os.system("python /root/Documents/nmap_auto_script_project/nmap_auto_script_demo.py")
