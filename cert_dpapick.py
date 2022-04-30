'''
Doing it with DPAPICK3

'''
import os, sys
from dpapick3.probes import certificate
from dpapick3 import blob, masterkey, registry

sid = ''
password = ''

i = os.scandir('./Crypto/RSA')
for d in i:
    if (d.is_dir() and (d.name[0:3] == 'S-1')):
        sid = str(d.name)
        print("Found SID : %s " % sid)
if sid == '':
    sys.exit('No SID found')


print("*" * 80 )
print("Extracting Public part of the certificate")
print("*" * 80 )

for pub_cert in os.scandir('./My/Certificates/'):
    with open(pub_cert.path,'rb') as file:
        while r := file.read(1):
            if (r.hex() == '30'):
                r = file.read(1)
                if (r.hex() == '82'):
                    pos = file.tell() -2
                    print("%s -> found %d" % (pub_cert.name,pos))
                    file.seek(pos)
                    fw = open(os.path.join('DER',pub_cert.name + '.der'),'wb')
                    fw.write(file.read())
                    fw.close()
                    break
masterkey_location = os.path.join('Protect', sid)

for priv_cert in os.scandir(os.path.join('./Crypto/RSA',sid)):
    with open(priv_cert.path, "rb") as f:
        binary = f.read()
        cert = certificate.PrivateKeyBlob(binary)
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(masterkey_location)
        #print(cert)
        try:
            cert.try_decrypt_with_password(password,mkp,sid)
            if (cert.flags.cleartext):
                print(cert.export())
                fw = open(os.path.join('PVK',priv_cert.name + '.pem'), 'w')
                fw.write(cert.export())
                fw.close()
        except:
            print("Not valid decryption or private key")
        print("-" * 80 )

