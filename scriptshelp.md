# Scripts

I did some scripts to help with the process when you have a lot of certificates, 
they are *somehow raw*, and **you need to modify paths on the files** to match my filestree.
You also depends on some tools, those are on each of the steps


You have to end having three folders, called *"My" "Protect"* and *"Crypto"*. You then manually have to create two more enmpty folders *DER* and *PVK*

Copy **My** directory located in:
%appdata%/Microsoft/SystemCertificates/My/Certificates/47548351737BE8BE60E20450C6A54569C1761C71
to your **My** folder

copy Masterkey located in
%appdata%/Microsoft/Protect/
to your **Protect** folder

Then the private parts of the certificate that are in %appdata%/Microsoft/Crypto/
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
  
Pass as parameters, -f the location of the file, -m the location of the Masterkey files --sid the SID of the user, -p password or --no-pass to try with a blank password
Script will export the certificate as a PEM file

Requisites: impacket

  **Linux - batch recovery - batchpvkdump.sh**
  
  This is very useful when you have a lot of certificates (more than one also) :D
  Edit the bactckpvkdump.sh, set your settings form cert_dpapi.py as is stated up, edit SID, pass etc, it will decrypt all the private parts, and fail 
  on the ones that are not certificates, at the end of this process you have to had some files on the PVK directory.
  
  
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
