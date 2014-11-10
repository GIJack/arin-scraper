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

#argument parsing code.
import argparse

parser = argparse.ArgumentParser(description='''This app parses data about ASNs and IP address ranges from ARIN Statistics Files, and look for hosts based on system name ARIN's Status files can be found on their FTP server here:
ftp://ftp.arin.net/pub/stats/''')
parser.add_argument("filenames",nargs='+',help="files to proccess")

data_type = parser.add_argument_group("Data Types","return/proccess lines matching these types")
data_type.add_argument("-a","--all",help="All Information(equiv of -i46n)",action="store_true")
data_type.add_argument("-i","--info",help="Metadata Information",action="store_true")
data_type.add_argument("-4","--ipv4",help="IPv4 IP Blocks",action="store_true")
data_type.add_argument("-6","--ipv6",help="IPv6 IP Blocks",action="store_true")
data_type.add_argument("-n","--asn",help="Autonomous System Numbers(ASN)",action="store_true")

filter_type = parser.add_argument_group("Filtering Options","filter data according to the following options")
filter_type.add_argument("-b","--before-date",help="List entries before specified date. Use 8 digit YEARMONTHDAY format",type=int)
filter_type.add_argument("-e","--after-date",help="List entries after specified date. Use 8 digit YEARMONTHDAY format",type=int)
filter_type.add_argument("-r","--regex",help="Regular Expression. Only Use Entries That Match(not implemented yet)",action="store_true")

proc_opts = parser.add_argument_group("Proccessing","Use NMAP and/or whois to expand IP Address Ranges and ASNumbers into more IP ranges and IP addresses respectively.")
proc_opts.add_argument("-N","--nmap",help="Scan Matching IP Address Ranges with NMAP",action="store_true")
proc_opts.add_argument("-O","--nmap-opts",help="Command line options to use with NMAP, defaults are:'-T5 -sn --max-retries 5'",type=str,default='-T5 -sn --max-retries 5')
proc_opts.add_argument("-w","--asn2ipblocks",help="Use 'whois' To Find IPaddress Blocks Associated With ASNumber",action="store_true")
proc_opts.add_argument("-s","--whois-server",help="ARIN Whois Server To User",type=str)

dict_group = parser.add_argument_group("Dictionary Options","Specify list of country codes to use")
use_dict = dict_group.add_mutually_exclusive_group()
use_dict.add_argument("-C","--cc",help="Country Codes: Use specified country codes instead of built in lists(space seperated ISO 3166-1 valid entries)",type=str)
use_dict.add_argument("-M","--marks-list",help="Use Mark's List of Countries"+colors.fg.lightcyan+ colors.bold+"(default)"+colors.reset,action="store_true")
use_dict.add_argument("-S","--iso-list",help="Use List of Countries From ISO 3166-1(all of them)",action="store_true")
args = parser.parse_args()
def cidr_convert(total):
    '''Converts Total amount of IP addresses to coresponding cidr notation
       address block, takes a single number'''
    total = str(total)
    cidr_dict = {'16777216':"/8", '8388608':"/9", '4194304':"/10", '2097152':"/11", '1048576':"/12", '524288':"/13", '262144':"/14", '131072':"/15", '65536':"/16", '32768':"/17", '16384':"/18", '8192':"/19", '4096':"/20", '2048':"/21", '1024':"/22", '512':"/23", '256':"/24" ,'128':"/25", '64':"/26", '32':"/27", '16':"/28", '8':"/29"}
    try:
        return cidr_dict[total]
    except:
        return total

def date_convert(indate):
    '''When given a single 8 digit number for YEARMONTHDAY, converts into a standard date'''
    try:
        indate  = str(indate)
        year    = int(indate[:4])
        month   = int(indate[4:6])
        day     = int(indate[6:8])
        import datetime
        return datetime.date(year,month,day).strftime("%A %d. %B %Y")
    except:
        return "Unknown		"

def strip_comments(inList):
    '''Strips out lines that start with # from a list that contains a dump of a file. please note it does not work with lines that have comments at the end.'''
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
            #for every line in the file, use split to put the fields in variables of a class
            #line.strip("\n")
            line = line.split(d)
            #check if we have valid data. We should have 7 fields. If not, skip the line
            if len(line) < 7:
                continue
            # line is a list, with the following fields from 0 to 6. No, putting them into a class results in a 14 times increase in proccessing time
            # delegate, country, ip_ver, block, block size, timestamp, status
            if ver == "ipv4":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == "ipv4":
                    line[4] = cidr_convert(line[4])
                    outList.append(line)
            elif ver == "ipv6":
                if line[1] == cc and line[6].strip() == "assigned" and line[2] == "ipv6":
                    line[4] = "/"+line[4]
                    outList.append(line)
    return outList

def print_ip_block_list(ipBlockList,ver,print_opts):
    '''Prints IPBlocks, expands using tree structure if need be.'''
    #version is either ASN, IPv4, or IPv6. If the version is ASN, don't print the header, tread this as expansion from the previous level.
    #ipBlockList format is the same as the files, [1] being the country code, [3] being the ipblock name, or alternatively a list of IPblocknames with the ASN being entry [0](make this a dictionary?)
    if ver == "ASN":
        if type(ipBlockList[3]) == list:
            print(colors.fg.orange,ipBlockList[1],colors.reset+"	AS"+ipBlockList[3][0])
            if len(ipBlockList[3]) > 1:
                print("	  \\")
                for i in range(len(ipBlockList[3])):
                    if i == 0:
                        continue
                    else:
                        print("	  |-"+ipBlockList[3][i])
                        if print_opts == "expand":
                            print_ip_list(ipList[ipBlockList[3][i]],"expand")
        elif type(ipBlockList[3]) == str:
            print(colors.fg.orange,ipBlockList[1],colors.reset+"	AS"+ipBlockList[3])
    #we assume that the program was called with either -4 or -6, and is printing file data from ipv4 or ipv6 blocks, and this function is called to do that, and passed either "ipv4" or "ipv6" as the version.
    else:
        print(colors.bold,colors.fg.yellow,"	",ver,"Address blocks",colors.reset)
        print(colors.bold,"CC	IPBlock	 	CIDR",colors.reset)
        for i in range(len(ipBlockList)):
            line = ipBlockList[i]
            print(colors.fg.orange,line[1],colors.reset+"	"+colors.bold+colors.fg.cyan+line[3]+colors.reset+"	"+line[4])
            if print_opts == "expand":
                print_ip_list(ipList[line[3]+line[4]],None)

def print_ip_list(ipList,print_opts):
    '''prints IPs from an nmap scan, in the tree structure '''
    spacing="		"
    #if print_opts == "expand":
    #    spacing += "	"
    if len(ipList) > 0:
        print(spacing+"\\")
        for address in ipList:
            print(spacing+"|-"+address)

def list_AS_numbers(filelines):
    '''returns the lines of the list that are ASN entries, takes the filelist as unput'''
    outList = []
    for cc in countries:
        for line in filelines:
            line = line.split(d)
            if len(line) < 7:
                continue
            elif line[1] == cc and line[2] == "asn":
                outList.append(line)
    return outList

def print_AS_Numbers(asnlist,print_opts):
    '''Print all the Autonomous Systems listed in the file, takes one variable, a list with the filelines in it'''
    print(colors.bold,colors.fg.yellow,"  Autonomous System Numbers",colors.reset)
    print(colors.bold,"CC	ASNumber",colors.reset)
    for asn in asnlist:
        if "expand" == print_opts:
            print_ip_block_list(asn,"ASN",None)
        elif "expand twice" == print_opts:
            print_ip_block_list(asn,"ASN","expand")
        else:
            print(colors.fg.orange,asn[1],colors.reset+"	"+asn[3])

def ASN_list_ip_blocks(asnlist,mirror):
    '''Calls ASNWhois to get a list of ipblocks from ARIN databases, two opts, a list of ASNs, and whois mirror, None for defaults'''
    from asnwhois import ASNWhois
    outList = []
    outDict = {}
    for asn in asnlist:
        target = "AS" + asn[3]
        oldasn = asn[3]
        ipBlocks = ASNWhois.get_ipblocks(target, mirror)
        asn[3].insert(0, oldasn)
        outDict[asn[3]
        outList.append(asn)
    return outList

def nmapScanHosts(targetList,opts):
    '''Takes an input of a list of targets(see nmap help), and raw command line options for nmap, and
    scans all targets in targetList, and returns dictionary with, the subnet as a key, and a list of hosts as the value
    the options of -T5 -sn --max-retries 5 are default'''
    scanTargets = []
    for line in targetList:
           if line[2] == "asn":
               for i in range(len(line[3])):
                   if i == 0:
                       continue
                   scanTargets.append(line[3][i])
           else:
               scanTargets.append(line[3]+line[4])
    import nmap
    opts = str(opts)
    scanner = nmap.PortScanner()
    validHosts = []
    #scanner.scan(hosts=' '.join(scanTargets), ports=None, arguments=opts)
    for target in scanTargets:
        targetHosts = []
        scanner.scan(hosts=target, ports=None, arguments=opts)
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up':
                targetHosts.append(host)
        validHosts.append(targetHosts)
        targetHosts.insert(0,target)
    outDict = {}
    for host in validHosts:
        for i in range(len(host)):
            if i == 0:
                outDict[host[0]] = []
            else:
                outDict[host[0]].append(host[i])
    return outDict

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
##proccess the country list
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

#make sure the country list is sorted
countries = sorted(countries)

#We do this one file at a time. This program is file oriented, as in transforming data in an ARIN status file.
import sys, os.path
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
    #set up data structures to be used later.
    asn_list = []
    ipList = {}
    #ipv6List = {}
    ipv4BlockList = []
    ipv6BlockList = []
    class file_meta:
        filename = filename
        version, name, serial, total, startdate, enddate, offset = meta_list

    ### gather and proccess data into lists###
    ## Start with basic information gathering from the file
    #start with IP addresses
    if args.ipv4 == True or args.all == True:
        ipv4BlockList += list_ip_blocks(filelines,"ipv4")
    if args.ipv6 == True or args.all == True:
        ipv6BlockList += list_ip_blocks(filelines,"ipv6")
    #now do the same with ASNs.
    if args.asn == True or args.all == True:
        asn_list += list_AS_numbers(filelines)

    ## Transforms. Now we start to use external programs to proccess/transform data into what we want.
    #Start with the largest formation, the Autonomous System Number, use whois to get IPblocks. As of yet, we can't seem to find IPv6 data off ASN lookups, or differeniate. That will change eventually
    if args.asn2ipblocks == True and len(asn_list) > 1:
        ipv4BlockList += ASN_list_ip_blocks(asn_list,args.whois_server)
    #Now we get into IPBlocks, or IP Networks, we use nmap to transform these into invidual IPs.
    if args.nmap == True:
        if len(ipv4BlockList) >= 1:
            ipList.update(nmapScanHosts(ipv4BlockList,args.nmap_opts))
        if len(ipv6BlockList) >= 1:
            ipList.update(nmapScanHosts(ipv6BlockList,args.nmap_opts+" -6"))

    ### Print and output, Take processed data and return it ###
    ## Header data. Real easy, just re-formated to be human readable, nothing more.
    if args.info == True or args.all == True:
        print_metadata()

    ## IP address handling, if there is a -4 or a -6 in the command line
    #If version 4 blocks are requested, with no transform options
    useipv4 = args.ipv4 or args.all
    useipv6 = args.ipv6 or args.all
    if useipv4 == True and args.nmap != True:
        print_ip_block_list(ipv4BlockList,"IPv4",None)
    #same with version 6
    if useipv6 == True and args.nmap != True:
        print_ip_block_list(ipv6BlockList,"IPv6",None)
    #now check if nmap expansion is enabled
    if args.nmap == True:
        if useipv4 == True:
            print_ip_block_list(ipv4BlockList,"IPv4","expand")
        if useipv6 == True:
            print_ip_block_list(ipv6BlockList,"IPv6","expand")

    ##ASN handling
    useasn = args.asn == True or args.all == True

    if useasn == True and args.asn2ipblocks != True:
        print_AS_Numbers(asn_list,None)
    elif useasn == True and args.asn2ipblocks == True:
        if args.nmap != True:
            print_AS_Numbers(asn_list,"expand")
        #If nmap and whois are both selected, make a full tree:
        elif args.nmap == True:
            print_AS_Numbers(asn_list,"expand twice")
exit()
