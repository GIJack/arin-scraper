#!/usr/bin/env python3
# This is a library file for arin-scraper.py that handles line filtering
# Written by jack @ nyi
# Licensed under a BSD 3 clause license. see LICENSE

#field delimeter that ARIN uses
d="|"

def FilterDates(dateIn,operator,fileLines):
    '''Returns fileLines filtered for only lines that match the date. Operator is either of the strings "before" or "after"'''
    filteredLines = []
    for line in fileLines:
        #the line is a raw read from the file that uses "|" delimeted fields. split this into a list, so we can access each field from a list index. "d" is defined at the top of the file as "|"
        testline = line.split(d)
        #If there is less than seven fields, then the data is invalid. Skip this line.
        if len(line) < 7:
            continue
        #the sixth [5] field of an entry is the date stamp. Sometimes there is no datestamp, or the datestamp is blank. If so, ignore(mabey default "00000000", to before???)
        elif line[5] == "00000000" or line[5] == "":
            continue
        #Now we can check if the dates match. two sub functions, "before" and "after"
        try:
            if operator == "before":
                if int(testline[5]) < dateIn:
                    filteredLines.append(line)
            elif operator == "after":
                if int(testline[5]) > dateIn:
                    filteredLines.append(line)
        except:
          continue
    return filteredLines

def FilterCountryCodes(ccList,fileLines):
    '''Returns only filelines that match given country codes'''
    outList = []
    for line in fileLines:
        #format the line. strip the return character, and then split the fields of the line using field delimeters(d is "|")
        testline = line.split(d)
        #the second entry on the line [1] is the country code. If the country code matches, put it in the list
        try:
            if testline[1] in ccList:
                outList.append(line)
        except:
            continue
    return outList

def FilterRegex(regex,fileLines):
    '''performs a regular expression match against given file lines, return only those that match'''
    #same as above
    #regular expression is disabled for now, simply because its a being a real pain in the ass
    #import re
    outList = []
    for line in fileLines:
        testline = line.split(d)
        #Highly experimental, this probably won't work. This function isn't used right now.
        try:
            #fourth entry on the line [3] is the item name, either the ASN number, or IP network block.
            #if re.fullmatch(regex,testline[3]) != None: #yeah, thats commented out for now. good luck getting that working
            if regex in testline[3]:
                outList.append(line)
        except:
            continue
    return outList

def FilterSelect(select,fileLines):
    '''returns the exact matching fileline, and nothing else'''
    #same as above, except this selects exact maching items only, again [3], the fourth item on the line is the item name to match
    outList = []
    for line in fileLines:
        testline = line.split(d)
        try:
            if testline[3] == select:
                outList.append(line)
        except:
            continue
    return outList

