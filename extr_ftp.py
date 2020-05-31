"""
PCAP FILE EXTRACTOR

A SIMPLE TO USE PYTHON PROGRAM TO EXTRACT DATA TRANSFERED VIA FTP FROM ITS PCAP FILES. 

THE PROGRAM SUPPORTS EXTRACTING TXT, JPEG AND JPG FORMATS.

IDEA OF IPSITA HANSDAH (https://github.com/mikasacker)
PROGRAM DESIGNED BY SONAAL PRADEEP(https://github.com/sonaalPradeep)


"""
import argparse
import re
import os

from scapy.all import rdpcap

def port_condition(packet, port = 20):
	try:
		return (packet['TCP'].sport == port
			or packet['TCP'].dport == port)
	except:
		return False

def convert_hex(string):
	excp_letters = ['\\', 'r', 't', 'n']	

	if len(string) == 2:
		return string

	res_string = string[:2]
	string = "".join([hex(ord(letter)).lstrip('0x') 
						if letter not in excp_letters else letter for letter in string[2:]])

	string = res_string + string

	string = re.sub(r'\\r', '0d', string)
	string = re.sub(r'\\n', '0a', string)
	string = re.sub(r'\\t', '09', string)
	string = re.sub(r'\\\\', '5c', string)
	string = re.sub(r'\\27', '27', string)

	string = re.sub(r'n', hex(ord('n')).lstrip('0x'), string)
	string = re.sub(r't', hex(ord('t')).lstrip('0x'), string)
	string = re.sub(r'r', hex(ord('r')).lstrip('0x'), string)

	return string

def extract_image(file_name, packet):
	try:
		packet_data = str(packet['Raw'].load)[2:-1].split('\\x')
		packet_data = [capstr for capstr in packet_data if capstr != ""]		

		packet_data = [convert_hex(sub_str) for sub_str in packet_data]
		
		packet_data = "".join(packet_data)

		img_data = bytes.fromhex(str(packet_data))

		with open(file_name, 'wb') as f:
			f.write(img_data)

	except:
		print('Unexpected Error occured while extracting image')

if __name__ == '__main__':
	parser = argparse.ArgumentParser("Extract data from PCAP files. Defaults to extracting from FTP packets")
	parser.add_argument("file", help = "PCAP file to load")
	parser.add_argument("-s", "--save", action = 'store_true', help = "save raw data in file")
	parser.add_argument("-v", "--verbose", action = 'store_true', help = "echos debugging details")
	args = parser.parse_args()

	packet_list = rdpcap(args.file)	
	file_name, file_format = "", ""

	if args.save and ('raw.txt' in os.listdir()):
		os.remove('raw.txt')
		if(args.verbose):
			print("Removed File : raw.txt")

	for ind in range(len(packet_list)):
		try:
			line = str(packet_list[ind]['Raw'].load).lstrip("'b").rstrip("'")
			if args.save:
				with open('raw.txt', 'a+') as f:
					f.write(line + '\n')
				
			if line[:4] == 'RETR':
				file_name, file_format = line.split()[-1].split('.')
				file_format = file_format[:-4]

				if file_name + '.' + file_format in os.listdir():
					os.remove(file_name + '.' + file_format)
				continue

			elif line == r'226 Transfer complete.\r\n':
				file_name, file_format = "", ""
				continue

			if file_name != "" and port_condition(packet_list[ind]):
				if file_format == 'txt':
					with open(file_name + '.' + file_format, 'a+') as f:
						f.write('\n'.join(line.split(r'\n')))
				elif file_format == 'jpg' or file_format == 'jpeg' or file_format == 'png':
					extract_image('.'.join([file_name, file_format]), packet_list[ind])
					
					if(args.verbose):
						print("Retrieving File : {}".format('.'.join([file_name, file_format])))
				
		except:
			continue

	if args.save and args.verbose:
		print("Written File : raw.txt")
