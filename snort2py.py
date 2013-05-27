#!/usr/bin/python
import sys
import pprint 

from Snort2Py import ParseSnortRules

snort_rules = ParseSnortRules.ParseSnortRules()

data = snort_rules.parse()
# print str(data)
#print(str(len(data)))

max_match_group = 0
max_sid = 0
count_match_group = {}
# print >>sys.stderr, data
for snort_rule in data:
	match_group = snort_rule['match_groups']
	for group in match_group:
		for key_value in group:
			key = key_value[0]
			value = key_value[1]
			if key == "content":
				if value.startswith("User-Agent: "):
					print "sid:" + snort_rule['sid'] + ";" + value


	# # pprint.pprint(snort_rule)	
	# try:
	# 	count_match_group[len(snort_rule['match_groups'])] += 1
	# except:
	# 	count_match_group[len(snort_rule['match_groups'])] = 1
	# if len(snort_rule) > 0:
		
		# print str(snort_rule)
		# if len(snort_rule['match_groups']) > max_match_group:
		# 	max_match_group = len(snort_rule['match_groups'])
		# 	max_sid = snort_rule['sid']

# print("Max match=%d, sid=%s" % (max_match_group, max_sid))
#	print str(snort_rule)

#print str(count_match_group)
