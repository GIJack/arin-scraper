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

#All static lookup tables moved to the "Big Dictionary" file.
from bigDict import *

#until I find somewhere else to put this
#from asnwhois import *

#argument parsing code.
import argparse

parser = argparse.ArgumentParser(description='''This app parses data about ASNs and IP address ranges from ARIN Statistics Files, and look for hosts based on system name ARIN's Status files can be found on their FTP server here:
ftp://ftp.arin.net/pub/stats/''')
parser.add_argument("filenames",nargs='+',help="files to proccess")

filter_type = parser.add_argument_group("Filtering Options","show data that matches these parameters")
filter_type.add_argument("-a","--all",help="Display All Information(equiv of -i46n)",action="store_true")
filter_type.add_argument("-i","--info",help="Display Metadata From the First Line of the File",action="store_true")
filter_type.add_argument("-4","--ipv4",help="Display IPv4 IP Blocks",action="store_true")
filter_type.add_argument("-6","--ipv6",help="Display IPv6 IP Blocks",action="store_true")
filter_type.add_argument("-n","--asn",help="Display Autonomous System Numbers(ASN)",action="store_true")
filter_type.add_argument("-b","--before-date",help="List entries before specified date. Use 8 digit YEARMONTHDAY format",type=int)
filter_type.add_argument("-f","--after-date",help="List entries after specified date. Use 8 digit YEARMONTHDAY format",type=int)
nmap_opts = parser.add_argument_group("NMAP Options","discover hosts on matching IP address blocks using nmap IP scanner")
nmap_opts.add_argument("-N","--nmap",help="Scan Matching IP Address Ranges with NMAP",action="store_true")
nmap_opts.add_argument("-O","--nmap-opts",help="Command line options to use with NMAP",type=str,default='-T5 -sn --max-retries 5')
dict_group = parser.add_argument_group("Dictionary Options:","Specify list of country codes to use")
use_dict = dict_group.add_mutually_exclusive_group()
use_dict.add_argument("-C","--cc",help="Country Codes: Use specified country codes instead of built in lists(space seperated ISO 3166-1 valid entries)",type=str)
use_dict.add_argument("-M","--marks-list",help="Use Mark's List of Countries"+colors.fg.lightcyan+ colors.bold+"(default)"+colors.reset,action="store_true")
use_dict.add_argument("-S","--iso-list",help="Use List of Countries From ISO 3166-1(all of them)",action="store_true")
args = parser.parse_args()

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
    if indate == "":
       return "Unknown		"
    import datetime
    indate  = str(indate)
    year    = int(indate[:4])
    month   = int(indate[4:6])
    day     = int(indate[6:8])
    if indate == "00000000":
        return "Unknown		"
    else:
        return datetime.date(year,month,day).strftime("%A %d. %B %Y")

def strip_comments(inList):
    '''Strips out lines that start with # from a list that contains a dump of a file. returns a list without the lines that start with #. please not it does not work with lines that have comments at the end.(not needed for this program)'''
    fileLines = []
    for line in inList:
        li=line.strip()
        if not li.startswith("#"):
            fileLines.append(line)
    return fileLines

def print_metadata():
    '''Prints ARIN status file data in human readable format. '''
    print(colors.fg.lightgreen,colors.bold,"File Name: ",colors.reset,os.path.abspath(file_meta.filename))
    print(colors.fg.yellow,colors.bold,"File Format Version:",colors.reset,file_meta.version,colors.bold,colors.fg.yellow,"			Serial Number:",colors.reset,file_meta.serial)
    print(colors.fg.yellow,colors.bold,"Total Entries:",colors.reset,file_meta.total,colors.bold,colors.fg.yellow,"			Delegate:",colors.reset,file_meta.name.upper())
    print(colors.fg.yellow,colors.bold,"Oldest Entry:",colors.reset,date_convert(file_meta.startdate),colors.fg.yellow,colors.bold,"	Latest Entry:",colors.reset,date_convert(file_meta.enddate))
    print("  ------------------------------------------------------------")

def list_ip_blocks(filelines,ver):
    '''print all ip address blocks, two variables, first a list with all the lines of the current file
    second, the version of the IP protocol, either IPv4 or IPv6 '''
    outList= []
    for cc in countries:
        for line in filelines:
            line.strip("\n")
            line = line.split(d)
            if len(line) < 7:
                continue
            if ver == "ipv4":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == ver:
                    line[4] = cidr_convert(line[4])
                    outList.append(line)
            elif ver == "ipv6":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == ver:
                    line[4] = "/"+line[4]
                    outList.append(line)
    return outList

def print_ip_block_list(ipBlockList,ver):
    print(colors.bold,colors.fg.yellow,"	",ver,"Address blocks",colors.reset)
    print(colors.bold,"Country Code	IPBlock	 	CIDR Block",colors.reset)
    for line in ipBlockList:
        print(line[1]+"		"+line[3]+"	"+line[4])

def print_ip_list(ipList):
        print(colors.bold,colors.fg.yellow,"	IP Addresses",colors.reset)
        for ip in ipList:
            print(ip)

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
                outList.append(line)
    return outList

def nmapScanHosts(targetList,opts):
    '''Takes an input of a list of targets(see nmap help), and raw command line options for nmap, and
    scans all targets in targetList, and returns a list of valid hosts. the options of -T5 -sn --max-retries 5'''
    scanTargets = []
    for line in targetList:
           scanTargets.append(line[3]+line[4])
    import nmap
    opts = str(opts)
    scanner = nmap.PortScanner()
    validHosts = []
    scanner.scan(hosts=' '.join(scanTargets), ports=None, arguments=opts)
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            validHosts.append(host)
    return validHosts

def FilterDates(dateIn,operator,fileLines):
    '''three operators, an 8 digit number in the YEARMONTHDAY formart, a string with either "before", or "after", and the filelines list. Returned is the file list with only relivant dates'''
    filteredLines = []
    for line in fileLines:
        line.strip("\n")
        line = line.split(d)
        if len(line) < 7:
            continue
        if line[5] == "00000000" or line[5] == "":
            continue
        elif operator == "before":
            if int(line[5]) < dateIn:
                filteredLines.append(d.join(line))
        elif operator == "after":
            if int(line[5]) > dateIn:
                filteredLines.append(d.join(line))
    return filteredLines
#----Below here this is run in order, check to see if each test is called for, and run if applicable ----#

#proccess the country list

#default is using mark's list of countries.
countries = marksCountries
if args.cc != None:
    for country in ccLookupTable:
        if country in args.cc:
            args.cc = args.cc.replace(country,ccLookupTable[country])
    args.cc = args.cc.upper()
    countries = args.cc.split()
elif args.iso_list == True:
    countries = allCountries
elif args.marks_list == True:
    countries = marksCountries

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
    ### This section performs filtering on file lines before analyzation ###
    #Strip out comments
    filelines = strip_comments(filelines)
    #now check to see if we have valid data, if not, skip this file.
    meta_list = filelines[0].split(d)
    if len(meta_list) != 7:
        print(filename,"is not an ARIN statistics file!")
        continue
    #Now filter dates as set in args
    if args.before_date != None:
        filelines = FilterDates(args.before_date,"before",filelines)
    if args.after_date != None:
        filelines = FilterDates(args.after_date,"after",filelines)
    ### End filtering Section ###
    class file_meta:
        filename = filename
        version, name, serial, total, startdate, enddate, offset = meta_list
    ipList = []
    if args.info == True or args.all == True:
        print_metadata()
    if args.ipv4 == True or args.all == True:
        ipBlockList = list_ip_blocks(filelines,"ipv4")
        if args.nmap == True:
           ipList += nmapScanHosts(ipBlockList,args.nmap_opts)
        else:
            print_ip_block_list(ipBlockList,"IPv4")
    if args.ipv6 == True or args.all == True:
        ipBlockList = list_ip_blocks(filelines,"ipv6")
        if args.nmap == True:
           ipList += nmapScanHosts(ipBlockList,args.nmap_opts)
        else:
            print_ip_block_list(ipBlockList,"IPv6")
    if args.nmap == True:
        print_ip_list(ipList)

    if args.asn == True or args.all == True:
        list_AS_numbers(filelines)

exit()
