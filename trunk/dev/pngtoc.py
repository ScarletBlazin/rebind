#!/usr/bin/env python
#Converts binary files into #define C statements

from sys import argv

FILEI = argv[1]
FILEO = argv[2]
DNAME = argv[3]
DNAME_SIZE = DNAME + "_SIZE"

cdata = ''
data = open(FILEI).read()
data_len = len(data)

for c in data:
	cdata = "%s%s" % (cdata,hex(ord(c)).replace('0x','\\x'))

fp = open(FILEO,"a")
fp.write('#define %s %s\n' % (DNAME_SIZE,data_len))
fp.write('#define %s "%s"\n' % (DNAME,cdata))
fp.write('\n\n')
fp.close()
