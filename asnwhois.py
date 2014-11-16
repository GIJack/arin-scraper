#!/usr/bin/env python3

import subprocess
class ASNWhois:
    '''The ASN whois class uses UNIX 'whois' to return data about an ASN number'''
    def get_ipblocks(ASN,mirror):
        '''This function returns a list of all ip address blocks from a given ASN number, takes two options, the ASN number, as typed into whois, and the name of the whois server'''
        if mirror == None:
            indata = subprocess.check_output(["whois","-i","origin","-T","route",ASN])
        else:
            indata = subprocess.check_output(["whois","-h",mirror,"-i","origin","-T","route",ASN])
        indata = ASNWhois.infile_proc(indata)
        outList = []
        for line in indata:
            if "route:" in line:
                block = line.split()[1]
                outList.append(block)
        ASNWhois.value.ipblocks = outList
        ASNWhois.value.asn = ASN
        return outList

    def ASN_meta_data(ASN,mirror):
        '''Returns a dict with metadata from whois <ASNumber> with key:values for all data returned'''
        if mirror == None:
            indata = str(subprocess.check_output(["whois",ASN]))
        else:
            indata = str(subprocess.check_output(["whois",ASN,"-h",mirror]))
        indata = ASNWhois.infile_proc(indata)
        outDict = {}
        for line in indata:
            block = line.split()
            if len(block) > 1:
                key   = block[0].strip(":,;")
                value = ' '.join(block[1:])
                outDict[key] = value
        return outDict

    class value:
        '''Run ASN_meta_data() to populate this sub-class'''
        asn=""
        ipblocks = []

    def infile_proc(indata):
        '''Strip comments, control characters, and return the input in a list of lines'''
        indata = str(indata).strip()
        indata = indata.strip("b'")
        inList = indata.split('\\n')
        fileLines = []
        for line in inList:
            li=line.strip()
            if not li.startswith("%") and not li.startswith("#") and li != "":
                fileLines.append(line)
        return fileLines
