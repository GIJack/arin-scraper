#!/usr/bin/env python3
# This is a library file for arin-scraper.py that handles handles all the cost/value analysis
# Written by jack @ nyi
# Licensed under a BSD 3 clause license. see LICENSE

### Second Level Metrics ASN and IP Block scores ###

def netMetric(network):
    '''Generates a composite score value score for an network based on metrics'''
    # we start with 0 and then add 'points' for each item.
    metric = 0
    import random
    global ipList
    #use ping, traceroute, a count of IPs, and size of the network to 
    pingscore   = 0
    tracescore  = 0
    #countscore  = 0 #countscore is commented out because its reduntant to "pingscore" which is a normalized ping relivant count
    blockscore  = 0
    net_tokens = network.split("/")
    #networks are scored by size of network mask times 2, giving a weighted value to the ASN
    blockscore = ( 32 - int(net_tokens[1]) ) * 2
    #use three random IPs for ping instead of the entire range, 
    ping_primative = 0
    for i in range(3):
       rand_ip = random.choice(ipList[network])
       #This comment is here for absolutely no reason
       ping_primative += pingMetric(ipaddr,3,None)
    #normalize the results of the pings for the entire range, giving the score a weight of the amount of hosts relative to their ping times, from only three sample IPs
    pingscore = ping_primative * (len(ipList[network]/3))
    ## Next we do a traceroute on the first IP address in the block, this should be the router.
    tracescore = traceMetric(ipList[network][0],None)
    ## Last we do a count score that counts the amount of IPs in the block divided by eight
    #countscore = len(ipList[value]) / 8
    #make the composite metric by adding all the individual composites.
    #metric = blockscore + pingscore + tracescore + countscore
    metric = blockscore + pingscore + tracescore
    #finish by returing the composite metric
    return metric

def asnMetric(asnumber):
    '''Generates a composite score value score for an ASN based on network metrics'''
    # we start with 0 and then add 'points' for each item.
    metric = 0
    global asn_ipBlock_dict
    #get the scores for all the ipblocks in the ASN.   
    for ipblock in asn_ipBlock_dict[asnumber]:
        metric += netMetric[ipblock]
    return metric

def hostMetric(hostname):
    '''generates a composite score value for quality of a single IP/host'''
    metric = 0
    #This one is pretty straight forward. a host's score is simply its ping and traceroute scores.
    pingscore  = pingMetric(host)
    tracescore = traceMetric(host)
    metric = pingscore + tracescore
    return metric

### Primative Metrics ping, and traceroute ###
def pingMetric(host,count,opts):
    '''Uses sys_ping to compute the value metric score for an IP'''
    from utils.ping import sys_ping
    #start with a base score of zero and add from here.
    pingscore = 0
    #pass this along the the ping class in ping.py, generate scores
    sys_ping.ping(host,count,opts)
    #if we get no results from ping, just return 0, no score, adds nothing to the greater metric.
    if sys_ping.last.success == False:
        return 0
    #after a certain point, faster ping times have diminishing returns as far as usefulness, but because of the algorythm, exponential score increases. We cap this by max allowing the pingscore of any specific IP to return 2, or .5 milliseconds.
    avg_ping_time = float(sys_ping.last.avg_time)
    if avg_ping_time < 0.5:
        avg_ping_time = 0.5
    #the ping score is 1 over the average ping time with a best score of 2.0 being 0.5 ms
    pingscore += ( 1 / avg_ping_time )
    return pingscore

def traceMetric(host,opts):
    '''Uses sys_traceroute to compute value metric score for an IP'''
    from utils.traceroute import sys_traceroute
    import ipwhois
    #start with base score of zero
    tracescore = 0
    sys_traceroute.traceroute(host,opts)
    #check for failures. Failure returns nothing.
    if sys_traceroute.last.success == False:
        return 0
    ## For our first trick, we count the number of hops that match the network name of the specified host. We *might* have
    #get the name of the network the host is on from whois
    whois = ipwhois.IPWhois(host)
    hostNetName = whois.lookup()['nets'][0]['description']
    hopcount = 0
    #For every IP in the traceroute, now get the network name and add one to the count if it matches the host's network
    for hop in sys_traceroute.last.sequence:
        #second item in a list in a dictionary is the IP address
        hop_ip = sys_traceroute.last.sequence[hop][1]
        try:
            #USE ipwhois to get whois data from the IP address
            whois = ipwhois.IPWhois(hop_ip)
        except:
            #This will fail if there is a private IP somewhere in the chain, we simply ignore private IPs
            continue
        #now, grab the name of the network from whois
        hop_NetName = whois.lookup()['nets'][0]['description']
        #if the network name of the hop is the same as the network name of the target host, increment by 1
        if hop_NetName == hostNetName:
            hopcount += 1

    #generate a composite of amount hops to the target, minus how many are in the network, under maximum amount of hops. 
    distscore = (int(sys_traceroute.last.hops) - hopcount )
    #Min hops is limited to 5 to because raw arithmatic differs greatly from our needs at certain points
    if distscore < 5:
        distscore = 5
    distscore = ( int(sys_traceroute.last.max_hops) / distscore )
    #add the scores together
    tracescore = ( hopcount + distscore )
    return tracescore
