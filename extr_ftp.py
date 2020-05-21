import argparse
import tkinter 

from scapy.all import rdpcap

if __name__ == '__main__':
	parser = argparse.ArgumentParser("Extract data from PCAP files")
	parser.add_argument("file", help = "PCAP file to load")
	parser.add_argument("-g", "--gui", action = 'store_true', help = "open in gui")
	args = parser.parse_args()

	if args.gui:
		window = tkinter.Tk()
		window.title("PCAP data extractor")

		label = tkinter.Label(window, text = "GUI support is currently unavailable :(").pack()
		rad1 = tkinter.Radiobutton(window, text = "HTML", value = 0)
		rad2 = tkinter.Radiobutton(window, text = 'FTP', value = 1)

		window.geometry("350x200")
		window.mainloop()

	else:
		packet_list = rdpcap(args.file)	

		for ind in range(len(packet_list)):
			packet_list[ind].show()
			print(end = '\n\n')
