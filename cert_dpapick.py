'''
Doing it with DPAPICK3

'''
from dpapick3.probes import certificate
from dpapick3 import blob, masterkey, registry

file = './Crypto/RSA/S-1-5-21-2489364404-1414483991-3321145804-1001/88fc815a745a3310f6d696a6ae12d88d_71d94470-45d0-4d65-b5ff-8fbe5cd68abf'
masterkey_location = './Protect/S-1-5-21-2489364404-1414483991-3321145804-1001/'
with open(file, "rb") as f:
    binary = f.read()

cert = certificate.PrivateKeyBlob(binary)
mkp = masterkey.MasterKeyPool()
mkp.loadDirectory(masterkey_location)
#print(cert)
cert.try_decrypt_with_password('XXXXXXXPASSXXXXX',mkp,'S-1-5-21-2489364404-1414483991-3321145804-1001')
print(cert)
print("---")
print(cert.export())
