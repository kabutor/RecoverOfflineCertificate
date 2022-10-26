'''
Export certificate from Windows
Doing it with DPAPICK3

'''
import os, sys
from dpapick3.probes import certificate
from dpapick3 import blob, masterkey, registry
import OpenSSL
import argparse
import random

DEBUG=False

def check_associate_cert_with_private_key(cert, private_key):
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        raise Exception('private key is not correct: %s' % private_key)

    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    except OpenSSL.crypto.Error:
        raise Exception('certificate is not correct: %s' % cert)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        pfx = OpenSSL.crypto.PKCS12()
        pfx.set_privatekey(private_key_obj)
        pfx.set_certificate(cert_obj)
        name = (cert_obj.get_subject().CN).replace(" ","_")
        name = name + "_" + str(random.randint(1111,9999)) + "_password_12345.pfx"
        pfxdata = pfx.export(b'12345')
        with open(name, 'wb') as pfxfile:
            pfxfile.write(pfxdata)
        print("Saved P12 as : %s" % name)
        return True
    except OpenSSL.SSL.Error:
        return False
parser = argparse.ArgumentParser()
parser.add_argument("--userpath","-u", help="User profile folder",default='.', type=str)
parser.add_argument("--password", "-p", help="user password",default='')
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
                    certificates.append(file.read())
                    break
print("*" * 80 )
print("Decrypting Keys, this can take a while, please wait")
print("*" * 80 )

masterkey_location = os.path.join(add_path,'Protect', sid)

for priv_cert in os.scandir(os.path.join(add_path,'Crypto/RSA',sid)):
    with open(priv_cert.path, "rb") as f:
        binary = f.read()
        cert = certificate.PrivateKeyBlob(binary)
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(masterkey_location)
        if DEBUG:
            if ("FNMT" in (cert.description).decode('windows-1252')):
                print(cert.description)
                print(cert.flags)
            #print(mkp)
        try:
            cert.try_decrypt_with_password(args.password,mkp,sid)
            if (cert.flags.cleartext):
                c = cert.export()
                print("[o] Decrypted Key \n%s" % c)
                keys.append(c)
        except:
            print("[X]")
        print("-" * 80 )

if (len(keys)) > 0:
    print("*" * 80 )
    print("Exporting PKCS12/PFX using 12345 as the password")
    print("*" * 80 )

    for k in keys:
        for certificate in certificates:
            #Match certificate and private key
            check_associate_cert_with_private_key(certificate,k)
else:
    print("No keys decrypted")
