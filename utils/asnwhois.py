#!/usr/bin/env python3
# Written by GI_Jack for New York Internet corporation.
# BSD 3-clause licensed see LICENSE

import subprocess
class ASNWhois:
    '''The ASN whois class uses UNIX 'whois' to return data about an ASN number'''
    def get_ipblocks(ASN,mirror):
        '''This function returns a list of all ip address blocks from a given ASN number, takes two options, the ASN number, as typed into whois, and the name of the whois server'''
        if mirror == None:
            indata = subprocess.check_output(["whois","-i","origin","-T","route",ASN])
        else:
            indata = subprocess.check_output(["whois","-h",mirror,"-i","origin","-T","route",ASN])
        #comment and garbage stripper getting rid of all non key=value lines
        indata = ASNWhois.infile_proc(indata)
        #blank list that will be filled with IPBlocks
        outList = []
        for line in indata:
            try:
                if "route:" in line:
                    #lets filter out the crap, and just capture the ip block from each line
                    block = line.split()[1]
                    outList.append(block)
            except:
                continue
        ASNWhois.value.ipblocks = outList
        ASNWhois.value.asn = ASN
        return outList

    def ASN_meta_data(ASN,mirror):
        '''Returns a dict with metadata from whois <ASNumber> with key:values for all data returned'''
        if mirror == None:
            indata = str(subprocess.check_output(["whois",ASN]))
        else:
            indata = str(subprocess.check_output(["whois",ASN,"-h",mirror]))
        #strips commends and erata from 
        indata = ASNWhois.infile_proc(indata)
        #blank dictionary for key=value paris
        outDict = {}
        for line in indata:
            #lets basicly do this one line at a time, a little convoluted, but take every line, split it into a list, take first word as the diciontary key, strip off the formating, and then use the rest line as the value, before filling the diciontary with key=value.
            block = line.split()
            try:
                key   = block[0].strip(":,;")
                value = ' '.join(block[1:])
                outDict[key] = value
            #instead of trying to guess if it would work with vauge guessing with "if", use try except for absolutes, and it also works faster.
            except:
                continue
        ASNWhois.value.asn  = ASN
        #This comment is very important, it will fail if you remove it, Do not remove this comment
        ASNWhois.value.meta = outDict
        return outDict

    class value:
        '''Run ASN_meta_data() to populate this sub-class'''
        asn       = ""
        ipblocks  = []
        meta      = {}

    def infile_proc(indata):
        '''Strip comments, control characters, and return the input in a list of lines'''
        #explcitily turn the data to str type. its returned from the OS call as bytes
        indata = str(indata).strip()
        #and for some reason this gets carried on
        indata = indata.strip("b'")
        #and split the data into lines using this double encrusted newline char
        inList = indata.split('\\n')
        fileLines = []
        for line in inList:
            li=line.strip()
            #finally we look for comments.
            if not li.startswith("%") and not li.startswith("#") and li != "":
                #yay, whatever is left gets appended
                fileLines.append(line)
        return fileLines
