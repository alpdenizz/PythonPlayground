
#!/usr/bin/python

#apt-get install python-socks

import argparse
import socks
import socket
import sys
import random
# do not use any other imports/libraries

# took 6.0 hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer\'s TorChat ID')
args = parser.parse_args()

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket
soc = socks.socksocket()
ssoc = socks.socksocket()
# reads and returns torchat command from the socket
def read_torchat_cmd(s):
    c = s.recv(1)
    cmd = ''
    while(c != '\n'):
        cmd += c
        c = s.recv(1)
    return cmd

print "[+] Connecting to peer", args.peer
soc.connect((args.peer+".onion", 11009))
my_cookie = random.getrandbits(50)
cmd = "ping "+args.myself+" "+str(my_cookie)+"\n"

print "[+] Sending:", cmd[:-1]
soc.sendall(cmd)

print "[+] Listening..."
ssoc.bind(('127.0.0.1',8888))
ssoc.listen(0)
(ss,address) = ssoc.accept()
print "[+] Client %s:%s" % (address[0], address[1])

status_received = False
info_sent = False
peer_cookie = ''
while True:
    cmdr = read_torchat_cmd(ss)
    print "[+] Received:", cmdr
    if not status_received and cmdr.startswith('status'):
        status_received = True
    elif cmdr.startswith('ping'):
        peer_cookie = cmdr.split(" ")[-1:][0]
    elif cmdr.startswith('pong'):
        cookie_received = cmdr.split(" ")[-1:][0]
        if cookie_received == str(my_cookie):
            cmd = "pong "+peer_cookie+"\n"
            soc.sendall(cmd)
            print "[+] Sending:", cmd[:-1]
        else:
            print "[-] Cookie mismatch"
            sys.exit(1)
    elif cmdr.startswith('message'):
        print "[?] Enter message:",
        msg = raw_input()
        
        cmd = "message "+msg+"\n"
        soc.sendall(cmd)
        print "[+] Sending:", cmd[:-1]

    #elif status_received and not info_sent:
    #    cmd = "add_me"+"\n"
    #    soc.sendall(cmd)
    #    print "[+] Sending:", cmd[:-1]
    #    
    #    cmd = "status available"+"\n"
    #    soc.sendall(cmd)
    #    print "[+] Sending:", cmd[:-1]
        
    #    cmd = "profile_name Doorless"+"\n"
    #    soc.sendall(cmd)
    #    print "[+] Sending:", cmd[:-1]
    #    status_received = False
    #    info_sent = True
    
    elif status_received and not info_sent or cmdr.startswith('add'):
        cmd = "add_me"+"\n"
        soc.sendall(cmd)
        print "[+] Sending:", cmd[:-1]
        
        cmd = "status available"+"\n"
        soc.sendall(cmd)
        print "[+] Sending:", cmd[:-1]
        
        cmd = "profile_name Doorless"+"\n"
        soc.sendall(cmd)
        print "[+] Sending:", cmd[:-1]
        status_received = False
        info_sent = True