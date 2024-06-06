# RecoverOfflineCertificate
How to recover a certificate from a broken (offline) Windows box


If you have windows box you can't start, maybe the drive is broken, but you have in there some certificates you want to recover you can do it following this guide. I will use a mix of Linux and Windows tools, you need to be skilled with computers, this is not a simple process, as the certificate (PFX) that windows uses has a public certificate part and a private one encripted with DPAPI.

***Prerequisites***
- This assume you are retrieving the files from a Windows 10, if you use a differente Windows versions some paths, file locations, may differ.
- You need to be able to read the file structure of the broken/old Windows drive.
- I will use some tools on linux, and other from windows, I guess you can do it all from windows, but I'm more comfortable doing it this way.
- You need to know the password of the windows account the cert was installed. (Not the HELLO Pin, the password)

# Recover the cert (New way 20220501) (This is what you should use)

The new way is very easy, and much better, just install dpapick3 and execute *pkcs12_dpapi_export.py*, specify the user (-u) profile folder (C:\\users\\user_name) and the user password (-p) the rest is done automatically, you should have all the stored PKCS12/PFX files of that user with the password 12345.

i.e. *pkcs12_dpapi_export.py -u /media/root/unit/Users/kabutor --password MySecretPassword*

I find out that you need to have at least dpapick3 version 0.3.3 (I found the hard way that with dpapick version 0.3.2 is not working) 


*Changelog* - 2024 06 06: Added -l option (just to list the public certificates attributes and quit. Removes PyOpenSSL as it deprecates PKCS12, replaced with cryptography. Also some changes into the way the script handles the dpapi decryption it does improves the speed by 10 or more


# Recover the cert (Old way)

If you just want to recover the certificate the old way, in case the one above this is not working , go to this link where I guide you how to do it:
https://github.com/kabutor/RecoverOfflineCertificate/blob/master/scriptshelp.md





The rest of this Readme is just theory of how it works (not needed unless you want to know more)

# DO YOU WANT TO KNOW MORE?

## Extract the certificates

*Each certificate needs two files, the public and the private part, this example is asuming you only had one certificate in the computer, if you have several, you have to find a way to match them, each public part with the corresponding private one.*

You have to copy this files from the broken windows computer, for this example the credentials (user:password) of the user we want the retrieve the cert from is kabutor:supergreen

***Public certificate part***

This is located in:
```
c:\users\kabutor\Appdata\Roaming\Microsoft\SystemCertificates\My\Certificates\

 69A5C392AA570A62F99F9561F9DD8BD1E8E39B5C
```

This file has the public certificate part, but it has a header, we will remove it using binwalk to know where the header start and dd to copy it to a file, later we can use openssl to know who the cert belongs to.

```
$ binwalk 69A5C392AA570A62F99F9561F9DD8BD1E8E39B5C

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
276           0x114           Certificate in DER format (x509 v3), header length: 4, sequence length: 1690
```

276 is the header size we want to remove

```
$ dd if=69A5C392AA570A62F99F9561F9DD8BD1E8E39B5C of=certpub.der bs=1 skip=276

$ openssl x509 -inform der  -text -noout -in certpub.der

Certificate:                                                                                   
    Data:                                                                                      
        Version: 3 (0x2)
        Serial Number:                   
            1e:98:62:45:9b:ef:8f:94:57:2b:0a:3f:5b:a0:c4:be
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = ES, O = FNMT-RCM, OU = Ceres, CN = AC FNMT Usuarios
        Validity                       
--------------------[CUT]-------------------------
```

***Private Certificate***

We need to find the Credentials stored in the computer and the master key it was encrypted with, copy everything from (***important, almost all this files and directories are hidden!***):

C:\Users\kabutor\AppData\Roaming\Microsoft\Crypto\RSA\

and

C:\Users\kabutor\AppData\Roaming\Microsoft\Protect\

To find out the master key we need and to decrypt the certificate we will use mimkatz, we ask the credential file what masterkey we need to decrypt it
```
$ mimikatz # dpapi::capi /in:"C:\Users\kabutor\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-2331447286-1659246195-761725538-1001\1297a4b6f810e1252b3d693fca6d2144_3fa13103-421f-46af-8145-4145ab832541"
[snip]
 guidMasterKey      : {8d23af08-9f20-48f3-a487-4f0f9b13992e}
[snip]
```

Once we know, we will decrypt the masterkey with the password and the SID of the user, if the SID is on the path (the long number like S-1-5-21-XXXX ) mimikatz will pick automatically if not you need to specify it with /SID:

``` 
mimikatz # dpapi::masterkey /in:"C:\Users\kabutor\AppData\Roaming\Microsoft\Protect\S-1-5-21-2331447286-1659246195-761725538-1001\8d23af08-9f20-48f3-a487-4f0f9b13992e" /password:supergreen


***Auto SID from path seems to be: S-1-5-21-2331447286-1659246195-761725538-1001***

[masterkey] with password: supregreen (normal user)
  key : 5e6061fd32ebe306c73dc7f58506a2cb60a2f8a2265dea1b1544ad0c3834c7061bf96df151a9f7a4dbac3f63720ff5f3302ec95db106079576428c02546a5881
***sha1: 63a54b6d6508ec772cc6ff49058fd25c2723a526***
```

Now decrypt the private key to a file


```
mimikatz # dpapi::capi /in:"C:\Users\kabutor\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-2331447286-1659246195-761725538-1001\1297a4b6f810e1252b3d693fca6d2144_3fa13103-421f-46af-8145-4145ab832541" /masterkey:63a54b6d6508ec772cc6ff49058fd25c2723a526


        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   :
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_SIGN
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES
***        Private export : OK - 'dpapi_signature_capi_0_PvkTmp~b8fc158b-cea4-451d-b917-79822d349ddd.sign.rsa.pvk'***
```

This will create a file in the mimikatz folder with our private key *dpapi_signature_capi_0_PvkTmp~b8fc158b-cea4-451d-b917-79822d349ddd.sign.rsa.pvk*

## Build PFX Certificate

Now with openssl we rebuild and convert the certiicates into one PFX, just the commands, no explanation needed

```
openssl.exe x509 -inform DER -outform PEM -in 096BA4D021B50F5E78F2B9854A7461678EDAA006.der -out public.pem

openssl.exe rsa -inform PVK -outform PEM -in raw_exchange_capi_0_d209e940-6952-4c9d-b906-372d5a3dbd50.pvk -out private.pem
writing RSA key

openssl.exe pkcs12 -in public.pem -inkey private.pem -password pass:newpass -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

This will create a cert.pfx file we can install it on a computer using *newpass* as password.





# Backup OnlineCertificate == EXTRA BONUS SECTION

In this repo you also have three files to backup your certificates from windows, some people usually in Spain that work as as Accounting Manager and the like can have more than a 100 certificates in one computer. 
To export all into separate files with 12345 as password you can use Export-ClientCertificates.ps1 and run it (maybe you have to disable the script powershell policy or execute it with:

powershell -exec bypass .\Export-ClientCertificates.ps1 

Sometimes they are marked as non-exportable certificate, with these scripts you can export those if you combine it with Jailbreak, clone :
https://github.com/iSECPartners/jailbreak
And drop Export-ClientCertificates.ps1 and export_all_64bits.bat and run the latest one, that will run the powershell script under the jailbreak dll hook, and will enable you to export event the certificates marked as non-exportable.

Also if you want to import all into a new computer Import-AllPfx.ps1 will do that, imports all the PFX files on the same directory as the script.

***Extra note*** This scripts works on windows 10 assuming you have certificates in the user profile, as Windows does by default from Windows 8 and on, if you are in Windows 7 or the certs are in the Local Machine storage, you have to chaneg line 8 from:

$certPath = "Cert:\CurrentUser\My"

to

$certPath = "Cert:\LocalMachine\My"


Probably.


[You find this useful in any way and want to thank me, you can do so with a coffee, thanks](https://www.buymeacoffee.com/kabutor)

