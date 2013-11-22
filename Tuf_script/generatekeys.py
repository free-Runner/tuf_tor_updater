import repyhelper
# simple keypair creator...
import sys
import random

repyhelper.translate_and_import("rsa.repy")

# need to support random number generation
randomfloat = random.random

pubfn = sys.argv[1]+'.publickey'
privfn = sys.argv[1]+'.privatekey'

if len(sys.argv) == 3:
  keylength = int(sys.argv[2])
else:
  keylength = 1024 

print "Generating key files called '"+pubfn+"' and '"+privfn+"' of length "+str(keylength)+"."
print "This may take a moment..."

keys = rsa_gen_pubpriv_keys(keylength)

rsa_publickey_to_file(keys[0],pubfn)
rsa_privatekey_to_file(keys[1],privfn)

print "Success!"
