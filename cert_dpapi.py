#!/usr/bin/python3
# 
# Extract encripted DPAPI private RSA certificate and export into a PEM file, as with the mimikatz dpapi:capi
# Requisites:
# - The SID of the user (usualy is something like : S-1-5-21-3677721360-166281839-1125720576-1001
# - The encrypted file located in: Appdata\Roaming\RSA\<SID>\<file_name>
# - The masterkey used to encrypt the file, if you pass only the private RSA file this program will tell you the name of the needed one,
#   masterkeys are in: Appdata\Roaming\Protect\<SID>\<masterkey_file_name>
# - The password of the user
#  Initial version date 11/08/2021

from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, SHA1, MD4

from impacket.dpapi import *
import argparse
import sys, os

DEBUG=False


# Function to convert the decrypted DPAPI data into a Cryptodome RsaKey
def pvkblob_to_pkcs1(key):
    '''
    modified from impacket dpapi.py
    parse private key into pkcs#1 format
    :param key:
    :return:
    '''
    modulus = bytes_to_long(key['modulus'][::-1]) # n
    prime1 = bytes_to_long(key['prime1'][::-1]) # p
    prime2 = bytes_to_long(key['prime2'][::-1]) # q
    exp1 = bytes_to_long(key['exponent1'][::-1])
    exp2 = bytes_to_long(key['exponent2'][::-1])
    coefficient = bytes_to_long(key['coefficient'][::-1])
    privateExp = bytes_to_long(key['privateExponent'][::-1]) # d
    pubExp = int(key['pubexp']) # e
    # RSA.Integer(prime2).inverse(prime1) # u

    r = RSA.construct((modulus, pubExp, privateExp, prime1, prime2))
    return r

# Private Decrypted Private Key 
class PRIVATE_KEY_RSA(Structure):
    structure = (
        ('magic', '<L=0'),
        ('len1', '<L=0'),
        ('bitlen', '<L=0'),
        ('unk', '<L=0'),
        ('pubexp', '<L=0'),
        ('_modulus', '_-modulus', 'self["len1"]'),
        ('modulus', ':'),
        ('_prime1', '_-prime1', 'self["len1"] // 2'),
        ('prime1', ':'),
        ('_prime2', '_-prime2', 'self["len1"] // 2'),
        ('prime2', ':'),
        ('_exponent1', '_-exponent1', 'self["len1"] // 2'),
        ('exponent1', ':'),
        ('_exponent2', '_-exponent2', 'self["len1"]// 2'),
        ('exponent2', ':'),
        ('_coefficient', '_-coefficient', 'self["len1"] // 2'),
        ('coefficient', ':'),
        ('_privateExponent', '_-privateExponent', 'self["len1"]'),
        ('privateExponent', ':'),
    )
    def dump(self):
        print("magic             : %s " % ( self['magic']))
        print("len1              : %8x (%d)" % (self['len1'], self['len1']))
        print("bitlen            : %8x (%d)" % (self['bitlen'], self['bitlen']))
        print("pubexp            : %8x, (%d)" % (self['pubexp'], self['pubexp']))
        print("modulus           : %s" % (hexlify( self['modulus'])))
        print("prime1            : %s" % (hexlify( self['prime1'])))
        print("prime2            : %s" % (hexlify( self['prime2'])))
        print("exponent1         : %s" % (hexlify( self['exponent1'])))
        print("exponent2         : %s" % (hexlify( self['exponent2'])))
        print("coefficient       : %s" % (hexlify( self['coefficient'])))
        print("privateExponent   : %s" % (hexlify( self['privateExponent'])))
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        chunk = int(self['bitlen'] / 16)
        self['modulus']= self['modulus'][:chunk * 2]
        self['prime1']= self['prime1'][:chunk]
        self['prime2']= self['prime2'][:chunk]
        self['exponent1']= self['exponent1'][:chunk]
        self['exponent2']= self['exponent2'][:chunk]
        self['coefficient']= self['coefficient'][:chunk]
        self['privateExponent']= self['privateExponent'][:chunk * 2]
# PVK DPAPI BLOB when it has the SIG data
class PVKFile_SIG(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_Rsaheader_new', '_-Rsaheader_new', 'self["SigHeadLen"]' ),
        ('Rsaheader_new', ':'),                                            
        ('_Blob', '_-Blob', 'self["SigPrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["SigFlagsLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 


    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("RsaHeader : %s" %    (hexlify(self['Rsaheader_new']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# PVK DPAPI BLOB without SIG
class PVKFile(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_Rsaheader_new', '_-Rsaheader_new', 'self["HeaderLen"]' ),
        ('Rsaheader_new', ':'),                                            
        ('_Blob', '_-Blob', 'self["PrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["FlagsLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 


    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("RsaHeader : %s" %    (hexlify(self['Rsaheader_new']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# This class is the same as the previous two, its only used to see wich one of the previous clasess we will use
# sorry 
class PVKHeader(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        
        ('Remaining', ':'),

    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Masterkey decryption function, mostly copy pasted from impacket
def master(master_key,sid,password):

    #master_key
    fp = open(master_key, 'rb')
    data = fp.read()
    mkf= MasterKeyFile(data)
    if DEBUG:
        mkf.dump()

    fp.close()
    data = data[len(mkf):]
    mk = MasterKey(data[:mkf['MasterKeyLen']])

    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    #/key1, key2, key3 = self.deriveKeysFromUser(self.options.sid, password)

    # if mkf['flags'] & 4 ? SHA1 : MD4
    decryptedKey = mk.decrypt(key3)
    if decryptedKey:
        print('Decrypted key with User Key (MD4 protected)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key2)
    if decryptedKey:
        print('Decrypted key with User Key (MD4)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key1)
    if decryptedKey:
        print('Decrypted key with User Key (SHA1)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

#MAIN
# arguments

parser = argparse.ArgumentParser()
parser.add_argument("--file","-f", help="blob file name",default=None, type=str)
parser.add_argument("--masterkey", "-m", help="set masterkey directory location")
parser.add_argument("--sid", "-s", help="set SID(optional)")
parser.add_argument("--password", "-p", help="user password")
parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.add_argument("--out","-o",help="Output file name")
parser.set_defaults(nopass=False)
args = parser.parse_args()

just_mk = False
if ((args.file != None) and (os.path.isfile(args.file)) ):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Encrypted File: " + args.file )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "No File, use -f" )
if (args.masterkey):
    #if(os.path.isfile(args.masterkey)):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Masterkey location: " + args.masterkey )
    #else:
    #    print(bcolors.FAIL +" X "+ bcolors.ENDC + "Masterkey is not a file " )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "No Masterkey directory location, use -m " )
if (args.password):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Password in" )
elif (args.nopass):
    args.password= ''
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Will try with no password" )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "You need to supply password (-p) of use the --nopass " )
if (args.sid):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "User SID : " + args.sid )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "Need user SID (S-1...) as --sid " )
if args.file and not args.sid and not (args.password or args.nopass) and not args.masterkey:
    just_mk = True
elif not args.file or not args.sid or not (args.password or args.nopass) or not args.masterkey:
    print("Need masterkey file name, SID and password")
    sys.exit(2)

#data_blob
fp = open(args.file,'rb')
data = fp.read()
# Read the blob and see if it uses the SIG values or not
blob= PVKHeader(data)
if blob['SigHeadLen'] > 0:
    if DEBUG:
        print ("SIG")
    fp.seek(0)
    data=fp.read()
    blob=PVKFile_SIG(data)

else:
    if DEBUG:
        print("NO SIG")
    fp.seek(0)
    data=fp.read()
    blob=PVKFile(data)

fp.close()

if DEBUG:
    blob.dump()

if (just_mk):
    print("MasterKey needed: ", end="")
    print(bin_to_string(blob['Blob']['GuidMasterKey']).lower())
    sys.exit(2)
#See if MK is in the masterkey directory
mk_location =os.path.join(args.masterkey, bin_to_string(blob['Blob']['GuidMasterKey']).lower())
if (os.path.isfile(mk_location)):
    #else go for the decrypt
    key = master( mk_location , args.sid , args.password)
else:
    print("Can't find Masterkey file %s" % mk_location)
    sys.exit(2)

if DEBUG:
    print(hexlify(key).decode('latin-1'))

if (key):
    #According to the code on the mis-team/dpapick github the Export Flag is decoded using this hardcoded value as entropy
    entropy_pvk = blob['ExportFlag'].decrypt(key, b'Hj1diQ6kpUx7VC4m\0')
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "RSAFlag Decrypted")
    # the resulting decoded text have to be used as entropy for the decryption of the key, but if I use it, it will not decrypt
    # More testing is needed should be: 
    # decrypted = blob['Blob'].decrypt(key, entropy_pvk) 

    decrypted = blob['Blob'].decrypt(key)
    
    if decrypted is not None:
        print()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # Blob Content decrypted # #")
        print()
        try:
            print(decrypted.decode('utf-16-le'))
        except:
            pass
        if DEBUG:
            f = open('decrypted.bin','wb')
            f.write(decrypted)
            f.close()
        #create the RSA decripted structure
        rsa_temp = PRIVATE_KEY_RSA(decrypted)
        if DEBUG:
            rsa_temp.dump()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # RSA Structure created # #")

        #call the function that will convert that structure to a Cryptodome RsaKey Object
        rsa_file = pvkblob_to_pkcs1(rsa_temp)
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # RsaKey created # #")
        if (args.out == None):
            f = open('rsa_file.pem','wb')
        else:
            f = open(args.out,'wb')
        #export it
        f.write(rsa_file.export_key('PEM'))
        f.close()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # PEM Cert exported to pem file# #")
         
else:
    # Just print the data
    if DEBUG:
        blob.dump()
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "Error Decrypting, password/sid/blob may be wrong" )

