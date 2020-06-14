# PCAP-Data-Extractor

#### A simple to use python program to extract data transfered via FTP from its PCAP files. The program supports extracting TXT, JPEG and JPG formats. 

<i>Idea developed by </i>[Ipsita Hansdah](https://github.com/mikasacker).
<i>Program designed by </i>[Sonaal Pradeep](https://github.com/sonaalPradeep).

<hr>

## Packages Pre-requisites
The program runs and is tested on <b>Linux using python3.7.5</b>. The following packages are used in the program : scapy, tqdm and colorama. To install these packages, run the following command on your terminal:
```bash
pip3 install -r requirements.txt
# 'os', 're' and other commented modules aren't included in PyPi, or come as default
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
# or, to send regex style paths
python3 extr_ftp.py "path/to/files/*"
```

## Notes
* The program supports extracting textual data from HTTP packets, <b>but this wouldn't be recommended as sometimes the entire content isn't extracted.</b>
