import socket
import time
from struct import *
import struct
import binascii
import threading
import ctypes
import os
qDict={}
qDict_trace_route={}

def icmpport(number_of_packets,source_ip,destination_ip,interface,payload,length_of_payload,ttl):

		pth = str(os.getcwd())+"/library.so"
		if source_ip=="10.1.2.3" or source_ip=="10.1.2.4":
			ctypes.CDLL(pth).IcmpPortUnreachable(1,source_ip,destination_ip,"eth2",payload,length_of_payload,64)
		if source_ip=="10.1.0.1" or source_ip=="10.1.0.2":
			ctypes.CDLL(pth).IcmpPortUnreachable(1,source_ip,destination_ip,"eth3",payload,length_of_payload,64)
		print "Sent out an ICMP Packet from Node 4"


def icmp(number_of_packets,sip,dip,interface,new_payload,length_of_payload,ttl):
		pth = str(os.getcwd())+"/library.so"
		ctypes.CDLL(pth).IcmpTimeExceeded(1,sip,dip,interface,new_payload,length_of_payload,2)
		print "Sent out an ICMP Packet from Router 3"

#IPERF
def readQ():
	global qDict
	counter=1
	while True:
		if counter in qDict:
		   sip=qDict[counter]['source_ip']
		   dip=qDict[counter]['destination_ip']
		   if sip=="10.1.0.1" or sip=="10.1.0.2" or sip== "10.1.2.3" or sip == "10.1.2.4":
			sport=qDict[counter]['source_port']
			dport=qDict[counter]['destination_port']
			ttl=qDict[counter]['ttl']
			smac=qDict[counter]['source_mac']
			dmac=qDict[counter]['destination_mac']
			payload=qDict[counter]['payload']
			pth = str(os.getcwd())+"/library.so"

			if dip=="10.1.0.1" or dip =="10.1.0.2":
				ctypes.CDLL(pth).packetsraw(1,sport,dport,sip,dip,"eth2",str(payload),ttl,smac,dmac,len(payload))
			if dip=="10.1.2.3" or dip=="10.1.2.4":
				ctypes.CDLL(pth).packetsraw(1,sport,dport,sip,dip,"eth3",str(payload),ttl,smac,dmac,len(payload))
			print "Sent out an UDP Packet with TTL,Source Port,Dest Port",ttl,sport,dport
			counter=counter+1
		else:
			continue



def read_trace_route():
	global qDict_trace_route
	counter=1
	while True:
		if counter in qDict_trace_route:
		   sip=qDict_trace_route[counter]['source_ip']
		   dip=qDict_trace_route[counter]['destination_ip']
		   if sip=="10.1.0.1" or sip=="10.1.0.2" or sip== "10.1.2.3" or sip == "10.1.2.4":
			sport=qDict_trace_route[counter]['source_port']
			dport=qDict_trace_route[counter]['destination_port']
			ttl=qDict_trace_route[counter]['ttl']
			smac=qDict_trace_route[counter]['source_mac']
			dmac=qDict_trace_route[counter]['destination_mac']
			payload=qDict_trace_route[counter]['payload']
			pth = str(os.getcwd())+"/library.so"
			if dip=="10.1.0.1" or dip =="10.1.0.2":
				ctypes.CDLL(pth).packetsraw2(1,sport,dport,sip,dip,"eth2",str(payload),ttl,smac,dmac,len(payload))
			if dip=="10.1.2.3" or dip=="10.1.2.4":
				ctypes.CDLL(pth).packetsraw2(1,sport,dport,sip,dip,"eth3",str(payload),ttl,smac,dmac,len(payload))
			print "Sent out an UDP Packet with TTL,Source Port,Dest Port",ttl,sport,dport
			counter=counter+1
		else:
			continue



		

def packet_sniffer():
 s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
 first_packet=0
 last_packet=time.time()
 neg_ack=[]
 global qDict,qDict_trace_route
 packet_count=1 
 packet_count_trace_route=1	
 while True:
	packet = s.recvfrom(65565)
	packet = packet[0]
 	ethernetHeader=packet[0:14]
	ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
	#Destination MAC Address
	destination_mac_address= binascii.hexlify(ethrheader[0])
	#Source MAC Address
	source_mac_address= binascii.hexlify(ethrheader[1])
	#protocol= binascii.hexlify(ethrheader[2])
	destination_mac_address_array=[]
	source_mac_address_array=[]
	temp=''
	for i in destination_mac_address:
		temp=temp+i
		if len(temp)==2:
			destination_mac_address_array.append(str(temp))
			temp=''
	temp=''
	for i in source_mac_address:
		temp=temp+i
		if len(temp)==2:
			source_mac_address_array.append(str(temp))
			temp=''
	


	source_mac_address_array=['00','04','23','c7','a6','34']
	destination_mac_address_array=['00','04','23','c7','a6','3e']
	ip_header = packet[14:34]
	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	iph_length = ihl * 4

	#TTL
	ttl = iph[5]

	#Protocol . If ICMP then the protocol is set to 1 . If UDP protocol is set to 17
	protocol = iph[6]

	#Source IP Address
	source_ip = socket.inet_ntoa(iph[8])

	#Destination IP Address
	destination_ip = socket.inet_ntoa(iph[9])
	
	#Payload

	payload=packet[42:]
	#Decrementing the TTL
	changed_ttl=ttl-1
	#UDP Header
	udp_header=packet[34:42]
	udpHdr=struct.unpack("!HH4s",udp_header)
	source_port=udpHdr[0]
	destination_port=udpHdr[1]
	
	#source mac hex array
	source_mac_hex_address_array=[]
	#destination mac hex array
	destination_mac_hex_address_array=[]

	for item in source_mac_address_array:
		#print type(item)
		#item=item.decode('hex')
		#print type(item)
		item=int(item,16)
		source_mac_hex_address_array.append(item)
	
	for item in destination_mac_address_array:
		#item=int(item.decode('hex'),16)
		item=int(item,16)
		destination_mac_hex_address_array.append(item)

	destination_mac_hex_address_array = (ctypes.c_int * len(destination_mac_hex_address_array))(*destination_mac_hex_address_array)
	source_mac_hex_address_array = (ctypes.c_int * len(source_mac_hex_address_array))(*source_mac_hex_address_array)
	#if source_ip =="10.1.2.3" and destination_ip=="10.1.0.1":
	#if source_ip=="10.1.0.1" and destination_ip=="10.1.2.3":
		#print "Communication from node 1 to node 3"


	if int(protocol)==1 and (source_ip=="10.1.0.1" or source_ip=="10.1.0.2"):
		print "**********************************************************************888"
		length_of_payload=len(payload)
		icmpport_thread=threading.Thread(target=icmpport,args=(1,source_ip,destination_ip,"eth3",payload,length_of_payload,64))
		icmpport_thread.start()
		continue

		
	
	#For Traceroute from Lan1 to Lan0
	if int(protocol)==1 and destination_ip=="10.1.0.1" and (source_ip=="10.1.2.4" or source_ip=="10.1.2.3"):
		length_of_payload=len(payload)
		icmpport_thread=threading.Thread(target=icmpport,args=(1,source_ip,destination_ip,"eth2",payload,length_of_payload,64))
		icmpport_thread.start()
		continue		

	#For Traceroute from Lan1 to Lan0 to Lan1
	if int(changed_ttl)==0:
		interface=""
		if source_ip=="10.1.0.1" or source_ip=="10.1.0.2":		
			sip="10.10.1.2"
			interface="eth2"
		if source_ip=="10.1.2.3" or source_ip=="10.1.2.4":
			sip="10.1.2.1"
			interface="eth3"

		dip=source_ip
		new_payload=str(packet[14:34])+str(packet[34:42])+str(packet[42:])
		length_of_payload=len(new_payload)
		icmp_thread=threading.Thread(target=icmp,args=(1,sip,dip,interface,new_payload,length_of_payload,2))
		icmp_thread.start()
		continue



	
	#For Traceroute
	if int(protocol)==17 and len(payload)==32 and (source_ip=="10.1.0.1" or source_ip=="10.1.0.2" or source_ip =="10.1.2.3" or source_ip=="10.1.2.4"):
		qDict_trace_route[packet_count_trace_route]={}
		qDict_trace_route[packet_count_trace_route]['source_port']=source_port
		qDict_trace_route[packet_count_trace_route]['destination_port']=destination_port
		qDict_trace_route[packet_count_trace_route]['source_ip']=source_ip
		qDict_trace_route[packet_count_trace_route]['destination_ip']=destination_ip
		qDict_trace_route[packet_count_trace_route]['payload']=payload
		qDict_trace_route[packet_count_trace_route]['ttl']=changed_ttl
		qDict_trace_route[packet_count_trace_route]['source_mac']=source_mac_hex_address_array
		qDict_trace_route[packet_count_trace_route]['destination_mac']=destination_mac_hex_address_array
		packet_count_trace_route=packet_count_trace_route+1
		continue

	#Need to Optimise
	if int(protocol)==17 and (source_ip=="10.1.0.1" or source_ip=="10.1.0.2" or source_ip =="10.1.2.3" or source_ip=="10.1.2.4"):
		qDict[packet_count]={}
		qDict[packet_count]['source_port']=source_port
		qDict[packet_count]['destination_port']=destination_port
		qDict[packet_count]['source_ip']=source_ip
		qDict[packet_count]['destination_ip']=destination_ip
		qDict[packet_count]['payload']=payload
		qDict[packet_count]['ttl']=changed_ttl
		qDict[packet_count]['source_mac']=source_mac_hex_address_array
		qDict[packet_count]['destination_mac']=destination_mac_hex_address_array
		packet_count=packet_count+1
		continue
	
	if int(protocol)==1 and source_ip=="10.10.1.1":
		length_of_payload=len(payload)
		icmp_thread=threading.Thread(target=icmp,args=(1,source_ip,destination_ip,"eth3",payload,length_of_payload,2))
		icmp_thread.start()
		continue		
 s.close()


def main():
		thread=threading.Thread(target=readQ)
		thread.start()
		thread_trace_route=threading.Thread(target=read_trace_route)
		thread_trace_route.start()
		packet_sniffer()

main()
