import sys
import os.path

def usage():
    sys.exit('Usage: python ' + sys.argv[0] + ' State_Definition_json' + '  CFN_Template')

# check for single command argument
if len(sys.argv) != 3:
    usage()

statejson = sys.argv[1]
cfnfile = sys.argv[2]

# check file exists
if os.path.isfile(statejson) is False:
    print('File not found: ' + statejson)
    usage()
	
if os.path.isfile(cfnfile) is False:
    print('File not found: ' + cfnfile)
    usage()

# get a file object and read it in as a string
fileobj = open(statejson)
jsonstr = fileobj.read()
fileobj.close()

# do character conversion here
outstr = jsonstr.replace('"', '\\"').replace('\n', '\\n')


# Read in the file
with open(cfnfile, 'r') as file :
  filedata = file.read()

# Replace the target string
filedata = filedata.replace('{{STATEMACHINE_DEF}}', outstr)

# Write the file out again
with open(cfnfile, 'w') as file:
  file.write(filedata)