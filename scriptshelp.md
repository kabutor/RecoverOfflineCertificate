# Scripts

I did some scripts to help with the process, more useful when you have a lot of certificates, 
they are *somehow raw*, and **you need to modify paths on the files** to match my filestree.
This scrips sometimes dependes on some tools you need to have installed, those are specified on each of the steps


You have to end having three folders, called *"My" "Protect"* and *"Crypto"*. You then manually have to create two more empty folders named *DER* and *PVK*

Copy **My** directory located in:
%appdata%/Microsoft/SystemCertificates/My
to your **My** folder

copy Masterkey located in
%appdata%/Microsoft/Protect/
to your **Protect** folder

Then the private parts of the certificate that are in
%appdata%/Microsoft/Crypto/
to your **Crypto** folder

You now have all the needed files from the computer, lets go for the recovery

## 1 - Extract the public part of the certificate
  **strip_der.sh**

Bash script, **linux**.

Remove the useless header from the public certificates, you have to create a folder called
DER all the output files will be created there

Requisites: Binwalk, dd

## 2 - Extract the private part of the certificate

  **Linux - one certificate - cert_dpapi.py**
  
Pass as parameters, -f the location of the file(each of the files located into the **My** directory), -m the location of the Masterkey files (those are in the **Protect** directory) --sid the SID of the user( the SID is on the path (the long number like S-1-5-21-XXXX )), -p password or --no-pass if user has no password to log into windows, to try with a blank password
Script will export the certificate as a PEM file in the PVK directory

Requisites: impacket

  **Linux - batch recovery - batchpvkdump.sh**
  
  This is very useful when you have a lot of certificates (more than one also) :D
  Edit the batchpvkdump.sh, set your settings form cert_dpapi.py as is stated up, edit SID, pass etc, it will decrypt all the private parts, and fail 
  on the ones that are not certificates, at the end of this process some files will be on the PVK directory, those are the PVK private keys decrypted.
  
  Requisites: (same as before) impacket
  
  **Windows - decrypt_PVK.ps1**

Windows Powershell (run as powershell -exec bypass ./decrypt_PVK.ps1)

You need to edit line 5 and 6 with the SID and the password 
of the user (local password). DPAPI is encrypted using that pass.
That script use mimikatz to look for the masterkey that encrypt it, decrypt it with the password,
and then decrypt the PVK using that masterkey sha1 key.
The output of this script is all the PVK files in the root folder, create a folder named PVk and move all the files there.

If user has no pass, you have to set to $True the $emptypass option on line 7.

Requisites: mimikatz (disable Antivirus)

## 3 - Match the public and private parts
  **match_linux_pairs.sh**

Bash script, linux.

How to know what public file goes with what PVK key? Both files have to had the same value
of "Modulus"
https://kb.wisc.edu/iam/page.php?id=4064
This just read that value from each public certificate in DER and look for a match on PVK folder, if found,
it creates a PFX file with **12345 as the password**

Requisites: openssl
