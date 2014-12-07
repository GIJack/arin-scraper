#!/usr/bin/env python3
# Written by Jack @ nyi. Licensed under the FreeBSD license. See LICENSE
# Calls system(posix) traceroute and returns and makes the values accessable to python

class sys_traceroute:
    '''this class is a python wrapper for UNIX system ping command, subclass ping does the work, last stores data from the last systraceroute.traceroute'''
    def traceroute(target,opts):
        '''conducts a ping, returns the data and populates the "last" subclass'''
        import subprocess
        #most of this is copypasta'd from ping.py and ported
        indata = ""
        sys_traceroute.last.opts = opts
        sys_traceroute.last.host = target
        #actually do a syscall for the traceroute and output the data to indata. If ping fails to find a host, it returns error status 2, capture the error and return an error message
        try:
            if opts == None:
                indata = subprocess.check_output(["traceroute",target],stderr=subprocess.STDOUT)
            else:
                sys_traceroute.last.opts = opts
                indata = subprocess.check_output(["traceroute",opts,target],stderr=subprocess.STDOUT)
            #if this works, return a success, which is the default state.
            sys_traceroute.last.success = True
        except subprocess.CalledProcessError:
            #if ping returns an error code, return a failure, and mark the success flag as false
            sys_traceroute.last.success = False
            return {-1:"error: cannot traceroute host"}
        #strip trailing and leading characters, and split the lines into a list.
        indata = str(indata).strip("b'")
        indata = indata.strip()
        indata = indata.split('\\n')
        #Summary line is the one at the top, all we really need is the max_hops entry
        sum_line = indata[0]
        sys_traceroute.last.max_hops = sum_line.split()[4]
        #first line is the summary, already used, toss it, all that remains is the sequence
        del(indata[0])
        #last line is blank:
        indata.pop()
        #like ping we use a seq:data format for a dictionary. However since we need multiple data, the data is a 
        sequence = {}
        for hop in indata:
            hop   = hop.split()
            seq   = hop[0]
            host  = hop[1]
            try:
                ip    = hop[2].strip("()")
                ping1 = hop[3]
                ping2 = hop[5]
                ping3 = hop[7]
            except:
                ip    = "*"
                ping1 = "0"
                ping2 = "0"
                ping3 = "0"
            #Now fill them all into a list in a dictionary, with the sequence number as key
            sequence[seq] = [host,ip,ping1,ping2,ping3]
        sys_traceroute.last.sequence = sequence
        sys_traceroute.last.hops    = len(sys_traceroute.last.sequence)
        return sequence

    class last:
        host = ""
        opts = ""
        hops = 0
        max_hops = 0
        sequence = {}
