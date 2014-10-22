#!/usr/bin/env python3
# This script parses and proccess ARIN's textfiles from their FTP server.
# Original use was to look for IPs in countries for Mark to use with FTW to test connectivity around the world. This is now evolving into a proper application
# See https://my.nyi.net/tickets/view/143661
# Written by jack barber @ nyi GPL v2

# see arin_scrape.py --help for usage
# Status files are found here: ftp://ftp.arin.net/pub/stats/
# python lib for nmap backend http://xael.org/norman/python/python-nmap

#The delimeter for fields that ARIN uses
d="|"

#Counrties on Mark's list. See ticket in header.
marksCountries=['AO', 'BJ', 'BW', 'BF', 'BI', 'CM', 'CV', 'CF', 'TD', 'CD', 'GQ', 'EG', 'ER', 'ET', 'GA', 'GM', 'GH', 'GN', 'GW', 'GY', 'CI', 'KE', 'LS', 'LY', 'MG', 'MW', 'ML', 'MR', 'MU', 'YT', 'MA', 'MZ', 'NA', 'NE', 'NG', 'CG', 'RW', 'SN', 'SC', 'SO', 'ZA', 'SZ', 'TZ', 'TG', 'TN', 'UG', 'EH', 'ZM', 'ZW', 'AP', 'AS', 'AU', 'BD', 'BY', 'BT', 'MM', 'KH', 'CN', 'CX', 'FJ', 'PF', 'GU', 'HK', 'IN', 'ID', 'JP', 'KI', 'LA', 'MO', 'MY', 'MV', 'MH', 'MN', 'NP', 'NZ', 'KP', 'PK', 'PH', 'WS', 'SG', 'KR', 'LK', 'TW', 'TH', 'TO', 'VU', 'VN', 'GL', 'IS', 'EU', 'DZ', 'HG', 'BN', 'HR', 'CY', 'XK', 'LV', 'MK', 'MT', 'MD', 'ME', 'RS', 'SK', 'SI', 'AL', 'AD', 'DK', 'FO', 'FR', 'GI', 'VA', 'IE', 'IM', 'JE', 'LU', 'MC', 'PT', 'ES', 'GB', 'AT', 'BE', 'BG', 'CH', 'CZ', 'DE', 'EE', 'FI', 'GR', 'HU', 'IT', 'NL', 'LI', 'LT', 'NO', 'PL', 'RO', 'RU', 'SE', 'UA', 'AF', 'AM', 'AZ', 'BH', 'IO', 'GE', 'IR', 'IQ', 'IL', 'JO', 'KZ', 'KW', 'KG', 'LB', 'LR', 'OM', 'QA', 'SA', 'SD', 'SY', 'TJ', 'TR', 'TM', 'AE', 'UZ', 'YE', 'AG', 'AI', 'AQ', 'AR', 'AW', 'BS', 'BB', 'BZ', 'BM', 'BO', 'BR', 'VG', 'CL', 'CO', 'CR', 'CU', 'DM', 'DO', 'EC', 'SV', 'FK', 'GD', 'GT', 'HT', 'HN', 'JM', 'MS', 'MX', 'NI', 'PA', 'PY', 'PE', 'PR', 'SR', 'TT', 'UY', 'VI', 'VE']

#All ISO 3166-1 country codes, to make the script more unversal
allCountries=['AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BQ', 'BA', 'BW', 'BV', 'BR', 'IO', 'BN', 'BG', 'BF', 'BI', 'KH', 'CM', 'CA', 'CV', 'KY', 'CF', 'TD', 'CL', 'CN', 'CX', 'CC', 'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'CI', 'HR', 'CU', 'CW', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF', 'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KP', 'KR', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MK', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SX', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'SS', 'ES', 'LK', 'SD', 'SR', 'SJ', 'SZ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU', 'VE', 'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW']

class colors:
    '''abridged colors class for this script use as colors.[reset|bold|underline] or colors.fg.<colorname>'''
    reset='\033[0m'
    bold='\033[01m'
    underline='\033[04m'
    class fg:
        red='\033[31m'
        green='\033[32m'
        blue='\033[34m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        lightcyan='\033[96m'

#argument parsing code.
import argparse
parser = argparse.ArgumentParser(description='''This app parses data about ASNs and IP address ranges from ARIN Statistics Files. ARIN's Status files can be found on their FTP server here:
ftp://ftp.arin.net/pub/stats/''')
parser.add_argument("filenames",nargs='+',help="files to proccess")
parser.add_argument("-a","--all",help="Display All Information(equiv of -i46n)",action="store_true")
parser.add_argument("-i","--info",help="Display Metadata From the First Line of the File",action="store_true")
parser.add_argument("-4","--ipv4",help="Display IPv4 IP Blocks",action="store_true")
parser.add_argument("-6","--ipv6",help="Display IPv6 IP Blocks",action="store_true")
parser.add_argument("-n","--asn",help="Display Autonomous System Numbers(ASN)",action="store_true")
use_dict = parser.add_mutually_exclusive_group()
use_dict.add_argument("-C","--cc",help="Country Codes: Use specified country codes instead of built in lists(space seperated ISO 3166-1 valid entries)",type=str)
use_dict.add_argument("-M","--marks-list",help="Use Mark's List of Countries"+colors.fg.lightcyan+"(default)" + colors.reset,action="store_true")
use_dict.add_argument("-S","--iso-list",help="Use List of Countries From ISO 3166-1(all of them)",action="store_true")
args = parser.parse_args()

#the default
countries = marksCountries

if args.cc != None:
    args.marks_list=False
    args.cc = args.cc.upper()
    countries = args.cc.split()
elif args.iso_list == True:
    countries = allCountries
    args.marks_list=False
elif args.marks_list == True:
    countries = marksCountries

def cidr_convert(total):
    '''Converts Total amount of IP addresses to coresponding cidr notation
       address block, takes a single number'''
    total = str(total)
    cidr_dict = { '131072':"/15", '65536':"/16", '32768':"/17", '16384':"/18", '8192':"/19", '4096':"/20", '2048':"/21", '1024':"/22", '512':"/23", '256':"/24" ,'128':"/25", '64':"/26", '32':"/27", '16':"/28", '8':"/29"}
    if total in cidr_dict:
        return cidr_dict[total]
    else:
        return total

def date_convert(indate):
    '''When given a single 8 digit number for YEARMONTHDAY, converts into a standard date'''
    import datetime
    indate  = str(indate)
    year    = int(indate[:4])
    month   = int(indate[4:6])
    day     = int(indate[6:8])
    if indate == "00000000":
        return "Unknown		"
    else:
        return datetime.date(year,month,day).strftime("%A %d. %B %Y")

def print_metadata(file_meta):
    '''Prints ARIN status file data in human readable format. takes one option, a class with the file metadata '''
    print(colors.fg.lightgreen,colors.bold,"File Name: ",colors.reset,os.path.abspath(file_meta.filename))
    print(colors.fg.yellow,colors.bold,"File Format Version:",colors.reset,file_meta.version,colors.bold,colors.fg.yellow,"			Serial Number:",colors.reset,file_meta.serial)
    print(colors.fg.yellow,colors.bold,"Total Entries:",colors.reset,file_meta.total,colors.bold,colors.fg.yellow,"			Delegate:",colors.reset,file_meta.name.upper())
    print(colors.fg.yellow,colors.bold,"Oldest Entry:",colors.reset,date_convert(file_meta.startdate),colors.fg.yellow,colors.bold,"	Latest Entry:",colors.reset,date_convert(file_meta.enddate))
    print("  ------------------------------------------------------------")

def list_ip_blocks(filelines,ver):
    '''print all ip address blocks, two variables, first a list with all the lines of the current file
    second, the version of the IP protocol, either IPv4 or IPv6 '''
    print(colors.bold,colors.fg.yellow,"	",ver,"Address blocks",colors.reset)
    print(colors.bold,"Country Code	IPBlock	 	CIDR Block",colors.reset)
    outList= []
    for cc in countries:
        for line in filelines:
            line.strip("\n")
            line = line.split(d)
            if len(line) < 7:
                continue
            elif ver == "IPv4":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == ver.lower():
                    print(line[1]+"		"+line[3]+"	"+cidr_convert(line[4]))
                    outList.append(line[3]+cidr_convert(line[4]))
            elif ver == "IPv6":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == ver.lower():
                    print(line[1]+"		"+line[3]+"		/"+line[4])
                    outList.append(line[3]+line[4])
    return outList

def list_AS_numbers(filelines):
    '''Print all the Autonomous Systems listed in the file, takes one variable, a list with the filelines in it'''
    print(colors.bold,colors.fg.yellow,"	Autonomous System Numbers",colors.reset)
    print(colors.bold,"Country Code	AS Number",colors.reset)
    outList = []
    for cc in countries:
        for line in filelines:
            line = line.split(d)
            if len(line) < 7:
                continue
            elif line[1] == cc and line[2] == "asn":
                print(line[1]+"		"+line[3])
                outList.append(line[3])
    return outList

def nmapScanHosts(targetList,opts):
    '''Takes an input of a list of targets(see nmap help), and raw command line options for nmap, and
    scans all targets in targetList, and returns a list of valid hosts. the options of -T5 -sn --max-retries 5'''
    import nmap
    opts = str(opts)
    scanner = nmap.PortScanner()
    nmapCMDline='-T5 -sn --max-retries 5'
    nmapCMDline += opts
    validHosts = []
    scanner.scan(hosts=' '.join(targetList), ports=None, arguments=nmapCMDline)
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            validHosts.append(host)
    return validHosts

#----Below here this is run in order, check to see if each test is called for, and run if applicable ----#

import sys, os.path
#Now with more awesomesauce, we can now check as many files are entered on the command line, now except * and ? expansions for max win, and much grepping. proc_arininfo.py -a *|grep whatever now works
for filename in args.filenames:
#open target file and dump lines into a list
#check to see if the file exists, if not exit gracefully with error messaage
    if os.path.isfile(filename) == False:
        print(filename + ": No such file")
        sys.exit(1)
    #open the file and dump its lines into a list.
    infile = open(filename,"r")
    filelines = infile.readlines()
    infile.close()
    #Strip out comments
    filelines2 = []
    for line in filelines:
        li=line.strip()
        if not li.startswith("#"):
            filelines2.append(line)
    filelines = filelines2
    del(filelines2)
    #now check to see if we have valid data
    meta_list = filelines[0].split(d)
    if len(meta_list) != 7:
        print(args.filename,"File is not an ARIN statistics file!")
        continue
    class file_meta:
        version = meta_list[0]
        name = meta_list[1]
        serial = meta_list[2]
        total = meta_list[3]
        startdate = meta_list[4];enddate = meta_list[5]
        offset = meta_list[6]
        filename = filename

    if args.info == True or args.all == True:
        print_metadata(file_meta)
    if args.ipv4 == True or args.all == True:
        list_ip_blocks(filelines,"IPv4")
    if args.ipv6 == True or args.all == True:
        list_ip_blocks(filelines,"IPv6")
    if args.asn == True or args.all == True:
        list_AS_numbers(filelines)

exit()
