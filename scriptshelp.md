# Scripts

I did three scripts to help with the process when you have a lot of certificates, 
they are very raw, and you will need to modify paths of the files to match my filestree
I put all the files from the broken machine into "My" "Protect" and "RSA".
Public part of the certificate is in:

My/Certificates/47548351737BE8BE60E20450C6A54569C1761C71

Masterkey files are in 

Protect/S-1-5-21-XXXXXXXXXX-XXXXXXXX-XXXXXXXXX-1001/d68ce8a2-0d11-4555-ad67-bc7c6b68d18f

and the private parts are in Crypto/RSA/SID/numbers, you've got it.

***1 - strip_der.sh***

Bash script, linux.

Remove the useless header from the public certificates, you have to create a folder called
DER all the output files will be created there

Requisites: Binwalk, dd

***2 - decrypt_PVK.ps1***

Windows Powershell (run as powershell -exec bypass ./decrypt_PVK.ps1)

You need to edit line 5 and 6 with the SID and the password 
of the user (local password). DPAPI is encrypted using that pass.
That script use mimikatz to look for the masterkey that encrypt it, decrypt it with the password,
and then decrypt the PVK using that masterkey sha1 key.
The output of this script is all the PVK files in the root folder, create a folder named PVk and move all the files there
If user has no pass, you have to set to $True the $emptypass option on line 7.
Requisites: mimikatz (disable Antivirus)

***3 - match_pairs.sh***

Bash script, linux.

How to know what public file goes with what PVK key? Both files have to had the same value
of "Modulus"
https://kb.wisc.edu/iam/page.php?id=4064
This just read that value from each public certificate in DER and look for a match on PVK folder, if found,
it creates a PFX file with 12345 password

Requisites: openssl
