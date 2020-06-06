"""
PCAP FILE EXTRACTOR

A SIMPLE TO USE PYTHON PROGRAM TO EXTRACT DATA TRANSFERED VIA FTP FROM ITS PCAP FILES. 

THE PROGRAM SUPPORTS EXTRACTING TXT, JPEG AND JPG FORMATS.

IDEA OF IPSITA HANSDAH (https://github.com/mikasacker)
PROGRAM DESIGNED BY SONAAL PRADEEP(https://github.com/sonaalPradeep)
"""
import argparse
import re
import sys
import os
import glob

from scapy.all import rdpcap

from colorama import init, Fore
from tqdm import tqdm

def print_info(args):
	try:
		print(Fore.YELLOW + "PCAP file : " + args.file)
		print(Fore.YELLOW + 'Save raw file : ' + str(args.save))
		print(Fore.YELLOW + "Leave progress bar : " + str(args.bar))
		print(Fore.YELLOW + 'Verbosity Level : ' + str(args.verbose))
		print(Fore.YELLOW + 'Extraction data type : ' + ("HTTP" if args.http else "FTP"))
		print()
	except:
		print(Fore.RED + "Unexpected Error while printing argument information")

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
		tqdm.write(Fore.RED + 'Unexpected Error occured while extracting image : {}'.format(file_name))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = "Extract data from PCAP files. Defaults to extracting from FTP packets")
	parser.add_argument("file", type = str, help = "PCAP file to load. To extract multiple files, send regex style format in quotes")
	parser.add_argument("--version", action = "version", version = "v1.0")
	parser.add_argument("--http", action = 'store_true', help = "extract from http files")
	parser.add_argument("-s", "--save", action = 'store_true', help = "save raw data in file")
	parser.add_argument("-v", "--verbose", action = 'count', default = 0, help = "echos debugging details")
	parser.add_argument("-b", "--bar", action = "store_true", help = "leave tqdm progress bar after execution")
	args = parser.parse_args()
	
	init(autoreset = True)

	if(args.verbose == 2):
		print_info(args)

	if args.http:
		selected_port = 80
	else:
		selected_port = 20

	list_of_files = glob.glob(args.file)

	if len(list_of_files) == 0:
		print(Fore.RED + "No files with given name found")
		sys.exit()
		

	for iter_file_name in list_of_files:
		packet_list = rdpcap(iter_file_name)	
		file_name_parts = []
		raw_print_stat = False

		raw_file_name = iter_file_name.rstrip(".pcapng").rstrip(".pcap").split('/')[-1]
		raw_file_name = "raw_" + raw_file_name.split('.')[0] + ".txt"

		if args.save and (raw_file_name in os.listdir()):
			os.remove(raw_file_name)
			if(args.verbose):
				tqdm.write("Removed File : " + Fore.GREEN + raw_file_name)

		for ind in tqdm(range(len(packet_list)), desc = "Iterating thru Packets", leave = args.bar, unit = 'packets'):
			try:
				line = str(packet_list[ind]['Raw'].load).lstrip("'b").rstrip("'")
				if args.save:
					with open(raw_file_name, 'a+') as f:
						f.write(line + '\n')
					
				if line[:4] == 'RETR':
					file_name, file_format = line.split()[-1].split('.')
					file_format = file_format[:-4]

					file_name_parts.append([file_name + '.' + file_format, file_format])

					if file_name_parts[-1][0] in os.listdir():
						os.remove(file_name[-1][0])
					continue

				elif line == r'226 Transfer complete.\r\n':
					file_name_parts.pop(0)
					continue

				if file_name_parts != [] and port_condition(packet_list[ind], selected_port):
					if file_name_parts[0][-1] == 'txt':
						with open(file_name_parts[0][0], 'a+') as f:
							f.write('\n'.join(line.split(r'\n')))
					elif file_name_parts[0][-1] in ['jpg', 'jpeg', 'png']:
						extract_image(file_name_parts[0][0], packet_list[ind])
					
					if(args.verbose):
						tqdm.write("Extracted File : " + Fore.GREEN + "{}".format(file_name_parts[0][0]))

				if args.save and args.verbose and not raw_print_stat:
					tqdm.write("Written File : " + Fore.GREEN + raw_file_name)
					raw_print_stat = True

		

			except:
				continue

		print()
