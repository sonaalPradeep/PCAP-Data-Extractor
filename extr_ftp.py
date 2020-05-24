import argparse
import tkinter 
import re
import os

from scapy.all import rdpcap

def port_condition(packet):
	try:
		# port 20
		return (packet['TCP'].sport == 20
		or packet['TCP'].dport == 20)
	except:
		return False

if __name__ == '__main__':
	parser = argparse.ArgumentParser("Extract data from PCAP files. Defaults to extracting from FTP packets")
	parser.add_argument("file", help = "PCAP file to load")
	parser.add_argument("-g", "--gui", action = 'store_true', help = "open in gui")
	parser.add_argument("-s", "--save", action = 'store_true', help = "save raw data in file")
	args = parser.parse_args()

	if args.gui:
		window = tkinter.Tk()
		window.title("PCAP data extractor")

		label = tkinter.Label(window, text = "GUI support is currently unavailable :(").pack()

		window.geometry("350x200")
		window.mainloop()

	else:
		packet_list = rdpcap(args.file)	
		file_name, file_format = "", ""

		if args.save and ('raw.txt' in os.listdir()):
			os.remove('raw.txt')

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
					with open(file_name + '.' + file_format, 'a+') as f:
						f.write('\n'.join(line.split(r'\n')))
				
			except:
				continue

