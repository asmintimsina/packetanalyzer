#!/usr/bin/env python

from __future__ import print_function

import sys
import io
from datetime import datetime

import pcapng
from pcapng.blocks import SectionHeader, InterfaceDescription, EnhancedPacket
from scapy.layers.l2 import Ether
import scapy.packet
# To make sure all packet types are available
import scapy.all

import MySQLdb as mdb
con = mdb.connect('localhost', 'wireshark', 'wireshark', 'wiresharkAnalysis');
def dump_information(scanner):
  for block in scanner:
  	if isinstance(block, EnhancedPacket):
  		pprint_enhanced_packet(block)

def pprint_enhanced_packet(block):
    if block.interface.link_type == 1:
        _info = format_packet_information(block.packet_data)
        print("\n\n")
        print(_info)
    else:
        print('        Printing information for non-ethernet packets')
        print('        is not supported yet.')

    # print('\n'.join('        ' + line
    #                 for line in format_binary_data(block.packet_data)))

def format_packet_information(packet_data):
    decoded = Ether(packet_data)
    return format_scapy_packet(decoded)

def format_scapy_packet(packet):
	#fields = []
	length = len(packet.fields_desc)
	#print(length)
	#for idx,f in enumerate(packet.fields_desc):
	#	if f.name in packet.fields:
	#		print(f.name)
	#		val = f.i2repr(packet, packet.fields[f.name])
	#		if(length == 13 and (idx==8 or idx==10 or idx==11)):
	#			print(str(val))
	#			fields.append("str(val)")
	for idx,f in enumerate(packet.fields_desc):
		try:
			if(length ==13 and idx==8):
				fields = []
				proto = str(f.i2repr(packet, packet.fields["proto"]));
				src = str(f.i2repr(packet, packet.fields["src"]));
				dst = str(f.i2repr(packet, packet.fields["dst"]));
				fields.append(proto);
				fields.append(src);
				fields.append(dst);
				with con:
					cur = con.cursor()
					cur.execute("INSERT INTO Wireshark(Protocol,Source,Destination) VALUES('"+proto+"',"+src+","+dst+")")
				return fields;
				#print(f.i2repr(packet, packet.fields["proto"]))
				#print(f.i2repr(packet, packet.fields["src"]))
				#print(f.i2repr(packet, packet.fields["dst"]))
		except:
			pass
	if packet.payload:
		if isinstance(packet.payload, scapy.packet.Packet):
			return format_scapy_packet(packet.payload)


if __name__ == '__main__':
	
	with con:
		cur = con.cursor()
		cur.execute("DROP TABLE IF EXISTS Wireshark")
		cur.execute("CREATE TABLE Wireshark(Id INT PRIMARY KEY AUTO_INCREMENT, Protocol VARCHAR(25), Source VARCHAR(25), Destination VARCHAR(25))")
		#con.commit()
	#mdb.disconnect()
	if len(sys.argv) > 1:
		with open(sys.argv[1], 'rb') as fp:
			scanner = pcapng.FileScanner(fp)
			dump_information(scanner)

	else:
		with open("/home/vicarios/wireshark-log.pcapng", 'rb') as fp:
			scanner = pcapng.FileScanner(fp)
			dump_information(scanner)
