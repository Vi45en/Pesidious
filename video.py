


import os
import json
import random
import time
import pickle
import sys

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
#COMMON_IMPORTS = pickle.load(open(os.path.join(module_path, 'gym_malware/envs/controls/adversarial_feature_vector_directory/adversarial_imports_set.pk'), "rb"))

COMMON_IMPORTS = json.load(open(os.path.join(module_path, 'gym_malware/envs/controls/small_dll_imports.json'), 'r'))
COMMON_SECTION_NAMES = open(os.path.join(module_path, 'gym_malware/envs/controls/section_names.txt'), 'r').read().rstrip().split('\n')

def show(string1):
	print("\t|")
	#print("\t|")
	print(" \t-- [+] " + string1)
	
print("Malware : Ransomware")
while(True):
	time.sleep(2)
	action = random.randint(1,5)
	if(action == 1):
		show("Appended random bytes")
	if(action == 2):
		show("Appended random bytes to sections")
	if(action == 3):
		show("Packed")
	if(action == 4):
		show("Unpacked")
	if(action == 5):
		section = random.choice(COMMON_SECTION_NAMES)
		show("Added section " + section)
	if(action == 6):
		section = random.choice(COMMON_SECTION_NAMES)
		show("Renamed a section to : " + section)
	if(action == 7):
		libname = random.choice(list(COMMON_IMPORTS))
		func = len((list(COMMON_IMPORTS[libname])))
		show("Added " + libname + " with " + str(func) + " functions")
	if(action == 8):
		show("Removed Debug Information")







