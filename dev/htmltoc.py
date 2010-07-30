#!/usr/bin/env python
#Converts HTML documents into #define C statements

from sys import argv

FILEI = argv[1]
FILEO = argv[2]
DNAME = argv[3]
DNAME_SIZE = DNAME + "_SIZE"

data = open(FILEI,"r").read()

data_len = len(data)
data = data.replace("\\s","\\\\s")
data = data.replace("\\n","\\\\n")
data = data.replace("\\r","\\\\r")
data = data.replace("\n","\\n\\\n")
data = data.replace('"','\\"')

fp = open(FILEO,"a")
fp.write('#define %s %s\n' % (DNAME_SIZE,data_len))
fp.write('#define %s "%s"\n' % (DNAME,data))
fp.write('\n\n')
fp.close()
