#!/usr/bin/env python3

import subprocess
class ASNWhois:
    '''The ASN whois class uses UNIX 'whois' to return data about an ASN number''''
    def ipblocks(ASN,mirror):
    '''This function returns a list of all ip address blocks from a given ASN number, takes two options, the ASN number, as typed into whois, and the name of the whois server'''
        indata = subprocess.check_output(["whois","-h",mirror,"-i","origin","-T","route",ASN])
        indata = str(indata).split('\\n')
        indata = strip_arinfile_comments(indata)
        outList = []
        for line in indata:
            if "route:" in line:
                block = line.split()[1]
                outList.append(block)
        return outList

    def get_ASN_meta_data(ASN,mirror):
    '''This function returns a list with some metadata from whois <ASNumber>, in the following format:
       source,as_name,description,org,status,organization_name,organization_type,person,abuse_email'''
        indata = subprocess.check_output(["whois","-h",mirror,ASN])
        indata = str(indata).split('\\n')
        indata = strip_arinfile_comments(indata)
        outList = []
        for line in indata:
            if "source:" in line:
                block = line.split()[1]
                outList.append(block)
            elif "as-name:" in line:
                block = line.split()[1]
                outList.append(block)
            elif "desc:" in line:
                block = line.split("   ")[-1]
                outList.append(block)
            elif "org:" in line:
                block = line.split()[1]
                outList.append(block)
            elif "status:" in line:
                block = line.split()[1]
                outList.append(block)
            elif "org-name:" in line:
                block = line.split("   ")[-1]
                outList.append(block)
            elif "org-type:" in line:
                block = line.split()[1]
                outList.append(block)
            elif "person:" in line:
                block = line.split("   ")[-1]
                outList.append(block)
            elif "abuse-mailbox:" in line:
                block = line.split()[1]
                outList.append(block)
          meta.source,meta.as_name,meta.description,meta.org,meta.status,meta.organization_name,meta.organization_type,meta.person,meta.abuse_email = tuple(outList)
          return outList

    class meta:
        '''Run get_ASN_meta_data() to populate this sub-class'''
        source=""
        as_name=""
        descripion=""
        org=""
        status=""
        organization_name=""
        organization_type=""
        person=""
        abuse_email=""

def strip_arinfile_comments(inList):
    '''Strips out lines that start with % from a list that contains a dump of a file. returns a list without the lines that start with %. please not it does not work with lines that have comments at the end.(not needed for this program)'''
    fileLines = []
    for line in inList:
        li=line.strip()
        if not li.startswith("%"):
            fileLines.append(line)
    return fileLines

