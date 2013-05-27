import re
import os
import binascii

class ParseSnortRules:
	def __init__(self, snort_config="/etc/snort/snort.conf", rules_path="/etc/snort/rules/"):
		self.snort_config = snort_config
		self.rules_path = rules_path
		self.snort_group_keywords = ["content", "pcre"]
		self.snort_extra_information_keywords = ["reference", "sid", "rev", "msg", "flow", "classtype", "flags", "threshold"]
		self.snort_regexp_compile()

	def snort_regexp_compile(self):
		self.snort_re = {}
		self.snort_re['header'] = re.compile("^(\S+) (\S+) (\S+) (\S+) -> (\S+) (\S+).*\(msg")

	def get_colon_key_value(self, colon_key_value):
		key_value = colon_key_value.split(":")
		key = key_value[0]
		key = key.strip(" ")
		value = ""
		if len(key_value) > 1:
			value = key_value[1]
			if value.startswith('\"'):
				value = value.strip('\"')

		return key, value

	def string_unhexify(self, string):
		# Input: 'toto|3a 70|' Output 'toto:p'
		opening_bin_pos = -1
		closing_bin_pos = -1


		total_len = len(string)
		lost_len = 0
		i = 0
		while i < total_len:
			# print ("my string='%s' i=%d" % (string, i))
			if string[i] == "|":
				if (i > 0 and string[i-1] != "\\") or i == 0:
					if opening_bin_pos == -1:
						# We are opening
						opening_bin_pos = i
					else:
						# We are closing
						if opening_bin_pos != -1:
								closing_bin_pos = i
								hex_value = string[opening_bin_pos+1:closing_bin_pos]
								hex_value = hex_value.replace(' ','').upper()
								# print str(hex_value)
								try:
									str_ascii = binascii.unhexlify(hex_value)
								except TypeError:   # TypeError: Non-hexadecimal digit found
									return string

								# print("STR:%s;%d:%d;%i" % (string, opening_bin_pos, closing_bin_pos, i))
								string = string.replace(string[opening_bin_pos:closing_bin_pos+1], str_ascii)
								lost_len = lost_len + len(string[opening_bin_pos:closing_bin_pos+1]) - len(str_ascii)
								# We reinitialize to find for other values
								total_len = len(string)
								i = opening_bin_pos # We do not start from scratch. Sometime we have |7C 7C|; 
								closing_bin_pos = -1

								# print "total len=%d;opening bin pos %d; string:'%s'" % (total_len, opening_bin_pos, string) 						
								# if opening_bin_pos == 0 and string[0] == '|':
								# 	opening_bin_pos = 0
								# else:
								opening_bin_pos = -1

			i += 1

		return string

	def is_group_keyword(self, key):
		for group in self.snort_group_keywords:
			if key == group:
				return True

		return False

	def is_extra_information_keyword(self, key):
		for group in self.snort_extra_information_keywords:
			if key == group:
				return True

		return False

	def parse_single_rule_data(self, rule):
		# Remove '(' and ')\n'
		rule = rule[1:]
		rule = rule[:-3]
       		# print(rule)

		snort_rule = {}

		# Get the fields
		rule_keyvalues = rule.split(";")
		in_group = False
		group_name = ""
		group_list = []
		for single_keyvalue in rule_keyvalues:
			key, value = self.get_colon_key_value(single_keyvalue)
			if key == "content":
				# print "unhexify this value: %s" % (value) 
				value = self.string_unhexify(value)			
				# print "unhexified value: %s" % (value) 

			if self.is_group_keyword(key):
				if in_group:
					# We are already in a group, so we simply add it
					group_list.append(group_content)

				# print("%s,%s"%(key,value))

				in_group = True
				group_name = key
				group_content = []

			# When we have extra information, and were grouping, we stop grouping
			if self.is_extra_information_keyword(key):
				if not in_group:
					# Then we have a simple extra information keyword with no group
					snort_rule[key] = value
				else:
					group_list.append(group_content)

					in_group = False
					group_name = ""

			if in_group:
				normalized_keyvalue = [key, value]
				# print("We add to group content %s" % (str(normalized_keyvalue)))
				group_content.append(normalized_keyvalue)				

		snort_rule['match_groups'] = group_list
		# print str(group_list)
			# print("key=%s;value=%s" % (key, value))

		return snort_rule

	def parse_single_rule(self, rule):
		snort_rule = {}

		# Parse the snort ruleset header
		header_re = self.snort_re['header'].match(rule)
		if header_re:
			snort_header = {}
			snort_header['header_type'] = header_re.group(1)
			snort_header['header_proto'] = header_re.group(2)
			snort_header['header_ipsrc'] = header_re.group(3)
			snort_header['header_portsrc'] = header_re.group(4)
			snort_header['header_ipdst'] = header_re.group(5)
			snort_header['header_portdst'] = header_re.group(6)
			snort_content = self.parse_single_rule_data(rule[header_re.end()-4:])
			snort_rule = dict(list(snort_header.items()) + list(snort_content.items()))			
			# print(str(snort_rule))
			return snort_rule

		return snort_rule

	def parse(self):
		snort_list = []

		rulesdir = os.listdir(self.rules_path)
		for rule in rulesdir:
			extension = rule[-5:]
			if extension == "rules":
				rule_file = self.rules_path + os.sep + rule
				fp = open(rule_file, "rb")
				for line in fp:
					if line.startswith("alert"):
						snort_rule = self.parse_single_rule(line)
						if len(snort_rule) > 0:
							snort_list.append(snort_rule)
				fp.close()

		return snort_list

