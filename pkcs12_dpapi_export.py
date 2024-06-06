#!/usr/bin/python3

'''
Export certificate from Windows
Doing it with DPAPICK3

'''
import os, sys
from dpapick3.probes import certificate
from dpapick3 import blob, masterkey, registry
import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, PrivateFormat
from cryptography.x509.oid import NameOID
import argparse
import random

DEBUG=False

def check_associate_cert_with_private_key(cert, private_key):
    cert_pem = x509.load_der_x509_certificate(cert)
    private_k = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)
 
    # "Modulus match public with private cert part"
    mod_k = private_k.private_numbers().public_numbers.n
    mod_p = cert_pem.public_key().public_numbers().n
    if mod_k != mod_p:
        return False 
    name = (cert_pem.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value).replace(" ","_")
    password = "12345"
    
    encryption = (
         PrivateFormat.PKCS12.encryption_builder().
         kdf_rounds(50000).
         key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
         hmac_hash(hashes.SHA256()).build(f"{password}".encode())
    )
    # forge certs key with public cert only when modulus is the same will work, if not error is raised
    try:
        p12 = pkcs12.serialize_key_and_certificates( f"{name}".encode(), private_k, cert_pem , None, encryption )
        #name = (cert_obj.get_subject().CN).replace(" ","_")
        name = name + "_" + str(random.randint(1111,9999)) + "_password_12345.pfx"

        with open(name, 'wb') as pfxfile:
            pfxfile.write(p12)
        print("Saved P12 as : %s" % name)
        return True
    except ValueError:
        pass

parser = argparse.ArgumentParser()
parser.add_argument("--userpath","-u", help="User profile folder",default='.', type=str)
parser.add_argument("--password", "-p", help="user password",default='')
parser.add_argument("--list","-l", help="List only certificates", default=False, action='store_true')
#parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password") # need to test it it works with password='' or you need the hash
args = parser.parse_args()

certificates = []
keys = []
sid = ''
add_path = os.path.join(args.userpath,'AppData/Roaming/Microsoft/')

#Get SID
i = os.scandir(os.path.join(add_path,'Crypto/RSA'))
for d in i:
    if (d.is_dir() and (d.name[0:3] == 'S-1')):
        sid = str(d.name)
        print("Found SID : %s " % sid)
if sid == '':
    sys.exit('No SID found')


print("*" * 80 )
print("Extracting Public part of the certificate")
print("*" * 80 )

for pub_cert in os.scandir(os.path.join(add_path,'SystemCertificates/My/Certificates/')):
    with open(pub_cert.path,'rb') as file:
        while r := file.read(1):
            if (r.hex() == '30'):
                r = file.read(1)
                if (r.hex() == '82'):
                    pos = file.tell() -2
                    print("%s -> Offset at %d" % (pub_cert.name,pos))
                    file.seek(pos)
                    x509_raw=file.read()
                    certificates.append(x509_raw)
                    x509_s = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_raw )
                    print(str(x509_s.get_issuer().OU) + " " + str(x509_s.get_issuer().CN))
                    print("Not valid before: %s after: %s" % ( x509_s.get_notBefore().decode()[:8] ,x509_s.get_notAfter().decode()[:8]))
                    print(x509_s.get_subject())
                    print("#" * 50)
                    break

# List only up to here
if args.list == True:
    sys.exit()

print("*" * 80 )
print("Decrypting Keys, this can take a while, please wait")
print("*" * 80 )

masterkey_location = os.path.join(add_path,'Protect', sid)
mkp = masterkey.MasterKeyPool()
mkp.loadDirectory(masterkey_location)
print("Loaded Masterkeys") 
for priv_cert in os.scandir(os.path.join(add_path,'Crypto/RSA',sid)):
    with open(priv_cert.path, "rb") as f:
        binary = f.read()
        cert = certificate.PrivateKeyBlob(binary)
        #mkp = masterkey.MasterKeyPool()
        #mkp.loadDirectory(masterkey_location)
        if DEBUG:
            print(cert.flags)
            if ("FNMT" in (cert.description).decode('windows-1252')):
                print(cert.description)
                print(cert.flags)
            #print(mkp)
        try:
            cert.try_decrypt_with_password(args.password,mkp,sid)
            if (cert.flags.cleartext):
                c = cert.export()
                # Keys tend to be several times, skip repeated ones
                if c not in keys:
                    keys.append(c)
                    print("[o] Decrypted Key \n%s" % c)
                else:
                    if DEBUG:
                        print("[-] Dupe key")

        except:
            print("[X]")
        print("-" * 80 )

if (len(keys)) > 0:
    print("Len keys %i" % len(keys))
    print("*" * 80 )
    print("Exporting PKCS12/PFX using 12345 as the password")
    print("*" * 80 )

    for k in keys:
        for certificate in certificates:
            #Match certificate and private key
            check_associate_cert_with_private_key(certificate,k)
else:
    print("No keys decrypted")
