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
	# group = parser.add_mutually_exclusive_group()
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
		raw_data = []
		req_data = []

		if args.save and ('raw.txt' in os.listdir()):
			os.remove('raw.txt')

		for ind in range(len(packet_list)):
			try:
				# packet_list[ind].show()
				raw_data.append(str(packet_list[ind]['Raw'].load).lstrip('b'))
				if args.save:
					with open('raw.txt', 'a+') as f:
						f.write(raw_data[-1] + '\n')

				if(port_condition(packet_list[ind])):
					# packet_list[ind].show()
					req_data.append(packet_list[ind])
			except:
				continue

