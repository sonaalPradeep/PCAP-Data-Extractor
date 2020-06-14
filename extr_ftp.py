"""
PCAP FILE EXTRACTOR

A SIMPLE TO USE PYTHON PROGRAM TO EXTRACT DATA TRANSFERED VIA FTP FROM ITS PCAP FILES. 

THE PROGRAM SUPPORTS EXTRACTING TXT, JPEG AND JPG FORMATS.

IDEA OF IPSITA HANSDAH (https://github.com/mikasacker)
PROGRAM DESIGNED BY SONAAL PRADEEP (https://github.com/sonaalPradeep)
"""
import argparse
import re
import sys
import os
import glob

import uuid

from scapy.all import rdpcap

from colorama import init, Fore
from tqdm import tqdm

def print_info(args):
	"""
	This functions prints all the arguments taken by the argparse module. Use '-vv' on the terminal to enable.
	"""
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
	"""
	This function tests for whether the source and destination port for the correct port. Default port : FTP (20)
	"""
	try:
		return (packet['TCP'].sport == port
			or packet['TCP'].dport == port)
	except:
		return False

def convert_hex(string):
	"""
	This function deals with parsing and formatting the image in hex format to the format which can be used to save images
	"""
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
	"""
	The method called to convert images into the desired format and save it.
	"""
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
	# Setting argparse
	parser = argparse.ArgumentParser(description = "Extract data from PCAP files. Defaults to extracting from FTP packets")
	parser.add_argument("file", type = str, help = "PCAP file to load. To extract multiple files, send regex style format in quotes")
	parser.add_argument("--version", action = "version", version = "v1.4")
	parser.add_argument("--http", action = 'store_true', help = "extract from http files")
	parser.add_argument("-s", "--save", action = 'store_true', help = "save raw data in file")
	parser.add_argument("-v", "--verbose", action = 'count', default = 0, help = "echos debugging details")
	parser.add_argument("-b", "--bar", action = "store_true", help = "leave tqdm progress bar after execution")

	args = parser.parse_args()
	
	# For colorama. 'autoreset' set to True, else the color needs to be reset every time.
	init(autoreset = True)

	# Prints argparse information as set by user
	if(args.verbose == 2):
		print_info(args)

	# By default, extract FTP packets, else extract from HTTP packets
	selected_port = 20 if args.http else 80

	# Provides for Linux style path input. Find names of all files and sort
	list_of_files = glob.glob(args.file)
	list_of_files.sort()

	# If no files are found, print error message and exit
	if len(list_of_files) == 0:
		print(Fore.RED + "No files with given name found")
		sys.exit()
		
	# Iterate through every file
	for iter_file_name in list_of_files:
		packet_list = rdpcap(iter_file_name)	
		file_name_parts = []
		raw_print_stat = False

		# Used to save the raw content of the packet
		raw_file_name = iter_file_name.rstrip(".pcapng").rstrip(".pcap").split('/')[-1]
		raw_file_name = "raw_" + raw_file_name.split('.')[0] + ".txt"

		# If the raw file already exists, delete file
		if args.save and (raw_file_name in os.listdir()):
			os.remove(raw_file_name)
			if(args.verbose):
				tqdm.write("Removed File : " + Fore.GREEN + raw_file_name)

		
		# Iterate through each packet in the file
		for ind in tqdm(range(len(packet_list)), desc = "Iterating thru Packets", leave = args.bar, unit = 'packets'):
			try:
				line = str(packet_list[ind]['Raw'].load).lstrip("'b").rstrip("'")

				# Save raw content
				if args.save:
					with open(raw_file_name, 'a+') as f:
						f.write(line + '\n')

				if args.http:
					# Used to extract text from http packets
					try:
						raw_load = str(packet_list[ind]['Raw'].load)
						res = re.findall(r"Content-Type: text/html", raw_load)
						
						h_file_name = uuid.uuid4().hex + '.txt'

						if res:
							with open(h_file_name, 'wb') as fd:
								fd.write(packet_list[ind]['Raw'].load)

							tqdm.write("Extracted File : " + Fore.GREEN + "{}".format(h_file_name))
					except:
						continue	
							
				else:
					# Used to extract content from ftp packets
					if line[:4] == 'RETR':
						# A statement to get a file was issued. The name of the file can be parsed from this line
						file_name, file_format = line.split()[-1].split('.')
						file_format = file_format[:-4]

						file_name_parts.append([file_name + '.' + file_format, file_format])

						if file_name_parts[-1][0] in os.listdir():
							os.remove(file_name[-1][0])
						continue

					elif line == r'226 Transfer complete.\r\n':
						# Statement shows that the file was transfered and this specific file name can be forgotten
						file_name_parts.pop(0)
						continue

					if file_name_parts != [] and port_condition(packet_list[ind], selected_port):
						if file_name_parts[0][-1] == 'txt':
							# Save text content
							with open(file_name_parts[0][0], 'a+') as f:
								f.write('\n'.join(line.split(r'\n')))
						elif file_name_parts[0][-1] in ['jpg', 'jpeg', 'png']:
							# Save image content
							extract_image(file_name_parts[0][0], packet_list[ind])
					
						if(args.verbose):
							# Prints when a file has been written. Use '-v' on terminal to enable
							tqdm.write("Extracted File : " + Fore.GREEN + "{}".format(file_name_parts[0][0]))

					if args.save and args.verbose and not raw_print_stat:
						# Prints when the raw file has been saved
						tqdm.write("Written File : " + Fore.GREEN + raw_file_name)
						raw_print_stat = True		

			except:
				continue

		print()
