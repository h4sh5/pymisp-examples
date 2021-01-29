#!/usr/bin/env python3
import os
from pymisp import PyMISP
# secret file
from keys import misp_url, misp_key,misp_verifycert
import os
import json
import sys

ELOG_DEBUG = 1
misp = None

def elog(*args, **kwargs):
    global ELOG_DEBUG
    if ELOG_DEBUG:
        print(*args, file=sys.stderr, **kwargs)


def init(url, key):
	#debug='json' will show json debug
    return PyMISP(url, key, misp_verifycert, debug=False) 


def getMaliciousURLs(lastPeriod):
	'''
	pull all malicious URLs for ingesting into IDS appliances
	lastPeriod examples:
		1d (1 day)
		365d (1 year)
		7d (week)
		30d 
		12h (12 hours)

	'''
	result = misp.search('attributes', type_attribute = 'url',
	 to_ids = True, timestamp=lastPeriod, returnFormat="text")

	lines = 0
	allines = ''
	for i in result['Attribute']:
		allines += i['value'] + '\n'
		lines += 1
	if ELOG_DEBUG:
		# lines = result.split('\n')
		elog(f"{lines} urls found")

	return allines

def getDomains(lastPeriod):
	result = misp.search('attributes', type_attribute = 'domain',
	 to_ids = True, timestamp=lastPeriod, returnFormat="text")

	lines = 0
	allines = ''
	for i in result['Attribute']:
		allines += i['value'] + '\n'
		lines += 1
	if ELOG_DEBUG:
		# lines = result.split('\n')
		elog(f"{lines} domains found")

	return allines

def getC2IPs(lastPeriod):
	'''
	C2 (command and control) IPs are destination IPs
	'''
	result = misp.search('attributes', type_attribute = 'ip-dst',
	 to_ids = True, timestamp=lastPeriod, returnFormat="text")

	lines = 0
	allines = ''
	for i in result['Attribute']:
		allines += i['value'] + '\n'
		lines += 1
	if ELOG_DEBUG:
		# lines = result.split('\n')
		elog(f"{lines} dest IPs found")

	return allines


if __name__ == '__main__':
	misp = init(misp_url, misp_key)
	elog("Mal urls past 2 yrs:")
	getMaliciousURLs('730d')
	elog("Mal urls past 1 yr:")
	getMaliciousURLs('365d')

	elog('---')
	elog("domains past 2 yrs")
	getDomains("730d")
	elog("domains past 1 yrs")
	getDomains("365d")

	elog('---')

	elog("dst ips past 2 yrs")
	getC2IPs("730d")
	elog("dst ips past 1 yrs")
	getC2IPs("365d")
