import subprocess
import sys

"""
Small script to get all static dependencies of Mac OS library
TODO: show relations
"""

def usage():
	print 'python get_dependencies.py <path to binary> <depth> (opt)<path to output>'
	
def clearOutput(dependencies):
	result = []
	dependencies = dependencies.split('\n')
	for dependency in dependencies:
		if len(dependency.split()) > 1:
			try:
				result.append((dependency.split())[0])
			except:
				pass

	return result


def getDependencies(parentDependencies):
	global depth
	result = []
	for dependency in parentDependencies:
		result.extend(clearOutput(subprocess.check_output(['otool', '-L', dependency])))
	if depth > 0:
		depth -= 1
		result.extend(getDependencies(result))
		
	return result

	
try:
	depth = int(sys.argv[2])
except:
	usage()
	exit()
	
result = list(set(getDependencies([sys.argv[1]])))
try:
	with open(sys.argv[3], 'w') as out:
		for lib in result:
			out.write(lib + '\n')
except:
	for lib in result:
		print lib