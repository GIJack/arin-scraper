arin-scraper
============

Python script that scrapes ARIN status files for information with nmap and whois backends for further data proccessing. The internet is a big place, and this program will help not only filter, but organize and help visualize

Please note this is still "pre-alpha", functionaily, formats, switchs, and data structures subject to change at any time without notice, for any reason.

Depenencies:
POSIX-enviroment(linux, UNIX, OSX, etc...), won't work on windows.
python3
python3-nmap
python3-argparse(for old versions of python before 3.2)

Recommended Usage:
Start by reading the help on the command line:

./arin_scraper.py --help
usage: arin_scraper.py [-h] [-a] [-i] [-4] [-6] [-n] [-b BEFORE_DATE]
                       [-e AFTER_DATE] [-r] [-N] [-O NMAP_OPTS] [-w]
                       [-s WHOIS_SERVER] [-C CC | -M | -S]
                       filenames [filenames ...]

This app parses data about ASNs and IP address ranges from ARIN Statistics
Files, and looks for hosts based on system name ARIN's Status files can be
found on their FTP server here: ftp://ftp.arin.net/pub/stats/

positional arguments:
  filenames             files to proccess

optional arguments:
  -h, --help            show this help message and exit

Data Types:
  return/proccess lines matching these types

  -a, --all             All Information(equiv of -i46n)
  -i, --info            Metadata Information
  -4, --ipv4            IPv4 IP Blocks
  -6, --ipv6            IPv6 IP Blocks
  -n, --asn             Autonomous System Numbers(ASN)

Filtering Options:
  filter data according to the following options

  -b BEFORE_DATE, --before-date BEFORE_DATE
                        List entries before specified date. Use 8 digit
                        YEARMONTHDAY format
  -e AFTER_DATE, --after-date AFTER_DATE
                        List entries after specified date. Use 8 digit
                        YEARMONTHDAY format
  -r, --regex           Regular Expression. Only Use Entries That Match(not
                        implemented yet)

Proccessing:
  Use NMAP and/or whois to expand IP Address Ranges and ASNumbers into more
  IP ranges and IP addresses respectively.

  -N, --nmap            Scan Matching IP Address Ranges with NMAP
  -O NMAP_OPTS, --nmap-opts NMAP_OPTS
                        Command line options to use with NMAP, defaults
                        are:'-T5 -sn --max-retries 5'
  -w, --asn2ipblocks    Use 'whois' To Find IPaddress Blocks Associated With
                        ASNumber
  -s WHOIS_SERVER, --whois-server WHOIS_SERVER
                        ARIN Whois Server To User

Dictionary Options:
  Specify list of country codes to use

  -C CC, --cc CC        Country Codes: Use specified country codes instead of
                        built in lists(space seperated ISO 3166-1 valid
                        entries)
  -M, --marks-list      Use Mark's List of Countries(default)
  -S, --iso-list        Use List of Countries From ISO 3166-1(all of them)


(For the program to run, you need to specify at least one datatype option.)

First, you need to download and verify your ARIN status files:
Download the files here, or on any of the delegate ftp servers(they all mirror):
		ftp://ftp.arin.net/pub/stats/

Next verify them, use the -i switch the read the metadata from the file, this will tell you things like the delegate name, time of last entry, file format, and printing and error if it can't read the metadata(letting you know the file is not an ARIN status file). This will let you know you are working with the correct files.

	./arin_scraper.py -i <filenames>

Next make sure you have some data:
	./arin_scraper.py -S -a <filenames>

	This might take awhile but it will print all data from the files.

From here on in, you can refine your search. The -i switch can help you locate what file has the information you are looking for so you can only use that file. the -4 and -6 switches will show what ipv4 and ipv6 networks are registered with ARIN. Only a small subsection of them are. For more complete information, you can resolve subnets from ASNumbers with whois.

To narrow your search you can date search -e(after) and -b(before), as well as specific your own --cc "list of countries", and will in the future include a --regex search. Please note, these only work on top level data.

Next comes expansions, once you've found top level data you want to resolve to lower order data, you can use the proccessing options.

-N, will use nmap to resolve ip network blocks into ip addresses, and will display them as leaves on a tree of all ip addresses found with nmap. the default options are a simple fast ping scan, but you can specify your own options to use with nmap with the -O option.

use -w, or --asn2ipblock will use whois to resolve the IPBlocks associated with ASN files, and the -h option can manually set a whois server for lookups(in case you don't get results you want.) If you combine -w, -N, and -n, the program will display all IP blocks related to matching ASN numbers, and then all IP addresses related to those blocks, in a nice easy to read tree view showing associations between the elements.
