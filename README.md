# PCAP-Data-Extractor

#### A simple to use python program to extract data transfered via FTP from its PCAP files. The program supports extracting TXT, JPEG and JPG formats.

<i>Idea developed by </i>[Ipsita Hansdah](https://github.com/mikasacker).
<i>Program designed by </i>[Sonaal Pradeep](https://github.com/sonaalPradeep).

<hr>

## Packages Pre-requisites
The program runs and is tested on <b>Linux using python3.7.5</b>. The following packages are used in the program : argparse, os and scapy. You might find the first three already installed by default. To install the other required packages, run the following command on your terminal:
```bash
pip3 install -r requirements.txt
```

## How to run the Program
The program comes with a well documented help page. Run the following command to access the help page:
```bash
python3 extr_ftp.py --help
# or
python3 extr_ftp.py -h
```
To run the program, enter the following command:
```bash
python3 extr_ftp.py path/to/pcap/file
```


