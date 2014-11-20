#!/usr/bin/env python3
#Written by Jack @ nyi. Licensed under the FreeBSD license. See LICENSE

class sys_ping:
    '''this class is a python wrapper for UNIX style ping command'''

    def ping(target,count,opts):
        '''conducts a ping, returns the data and populates the "last" subclass'''
        import subprocess
        count = str(count)
        indata = ""
        try:
            if opts == None:
                indata = subprocess.check_output(["ping","-c",count,target],stderr=subprocess.STDOUT)
            else:
                indata = subprocess.check_output(["ping","-c",count,opts,target],stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            indata = "ping: host unreachable"
        indata = str(indata).strip("b'")
        indata = indata.strip()
        indata = indata.split('\\n')
        indata.pop()
        avg_line     = indata.pop()
        summary_line = indata.pop()
        print(avg_line)
        return indata
    class last:
        '''This class stores data from last sys_ping.ping() use'''
        min_time,avg_time,max_time,mdev_time = 0,0,0,0
        host = ""
        opts = ""
        class seq:
            '''invidual ping replies'''
            default = ""
