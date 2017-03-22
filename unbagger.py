#!/usr/bin/env python

import re
from collections import Counter
import sys
import itertools

__version__ = '1.5'
__author__ = 'Dave Crawford'

REGEXPS = {}

REGEXPS['varFinder'] = r'^([a-z0-9]+)="([a-z0-9]+)"\s*$'
REGEXPS['deobFunc'] = r'([0-9a-z]+)\("[0-9a-z]+","?[0-9a-z]+"?\)'
REGEXPS['grabFunc'] = r'function\s+FUNCNAME\(([a-z0-9]+),([a-z0-9]+)\)(.*?)end function'
REGEXPS['grabStrings'] = r'FUNCNAME\("([a-z0-9]+)"\s*,\s*(["a-z0-9]+)\)'
REGEXPS['XORArray'] = r'Dim\s.*?([a-z0-9]+)\(\d\)'
REGEXPS['XORArrayItem'] = r'ARRAYNAME\((\d)\)[^=,\n]'
REGEXPS['XORKeyValue'] = r'ARRAYNAME\(ARRAYITEM\)\s*?=\s*?(\d+)'

VBSSCRIPT = ""
VARLIST = {}

def loadVBS(fname):
    global VBSSCRIPT

    with open(fname) as f:
        VBSSCRIPT = f.read()

    VBSSCRIPT.replace(r"\r\n", r"\n")

    # Find all variable assingments (ex. Hqn0I="23")
    rxp = re.compile(REGEXPS['varFinder'], re.I | re.M)
    m = rxp.findall(VBSSCRIPT)

    # Build table of variable assignments

    for var in m:
        VARLIST[var[0]] = var[1]

    return


def findDeobFunction():
    global VBSSCRIPT
    m = re.findall(REGEXPS['deobFunc'], VBSSCRIPT, re.I)
    return Counter(m).most_common(1)[0][0]


def grabStrings(funcName):
    global VBSSCRIPT
    regex = REGEXPS['grabStrings'].replace('FUNCNAME', funcName)
    matches = re.findall(regex, VBSSCRIPT, re.I | re.DOTALL)
    return matches


def deobString(arg1, arg2):
    if '"' in arg2:
        arg2 = arg2.replace('"','')
    else:
        arg2 = VARLIST[arg2.replace('"','')]

    retStr = ""
    s2h = []
    s2a = []

    # two-bytes per loop and convert hex string to int
    for i in range(0, len(arg1), 2):
        s2h.append(int(arg1[i:i+2], 16))

    iCycle = itertools.cycle(arg2)
    next(iCycle)

    # Convert character to ascii numeric
    for i in range(0, len(arg1)/2):
        s2a.append(ord(next(iCycle)))

    # XOR and convert ascii numeric to character
    for i in range(0, len(s2h)):
        retStr += chr(s2h[i] ^ s2a[i])

    return retStr


def findXORKey():
    global VBSSCRIPT

    # find the name of the array holding the possible XOR keys
    m = re.search(REGEXPS['XORArray'], VBSSCRIPT, re.I | re.DOTALL)
    xorArray = m.groups(0)[0]

    # find the single, non-assignment, reference to an array element
    m = re.search(REGEXPS['XORArrayItem'].replace('ARRAYNAME', xorArray), VBSSCRIPT, re.I | re.DOTALL)
    XORArrayItem = m.groups(0)[0]

    # extract the value assigned to the identified array value
    m = re.search(REGEXPS['XORKeyValue'].replace('ARRAYNAME', xorArray).replace('ARRAYITEM', XORArrayItem), VBSSCRIPT, re.I | re.DOTALL)
    XORKeyValue = m.groups(0)[0]
    return XORKeyValue


def defang(url):
    url = url.replace('http', 'hxxp')
    m = re.match(r'hxxp://(.*?)\/', url, re.I)
    li = m.groups(0)[0].rsplit('.', 1)
    li = '[.]'.join(li)
    url = url.replace(m.groups(0)[0], li)

    return url


def main(vbs):
    payloadURLS = []

    print "\n- Parsing VBS file..."
    loadVBS(vbs)
    
    print "\n- Locating de-obfuscation function..."
    deobFunc = findDeobFunction()

    print "    + Found {0}() as the de-obfuscation function...".format(deobFunc)
    print "\n- De-obfuscating strings...\n"

    for m in grabStrings(deobFunc):
        ds = deobString(m[0], m[1])

        if "http" in ds:
            ds = defang(ds)
            payloadURLS.append(ds)

    print "- Secondary payload loactions: "
    print '\n'.join('    {}'.format(i) for i in payloadURLS)

    XORKey = findXORKey()
    print "\n- Extracted XOR key for payloads: {0}\n\n".format(XORKey)


if __name__ == "__main__":
    try:
        f = sys.argv[1]
    except IndexError:
        print 'VBS file must be passed as an argument.'
        sys.exit(1)
    main(f)
