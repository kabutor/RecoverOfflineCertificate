#!/bin/bash
# Match Public and Private keys. 
# Modulus value has to be the same on each part of the certificate
# Bruteforce all and create the PFX file with 12345 pass

function lookfor(){

for file in PVK/*
do
	salida=$(openssl rsa -inform PVK -modulus -noout -in $file)
	#echo $1
	#echo $salida
	if [ "$1" = "$salida" ];then
		openssl x509 -inform DER -outform PEM -in $cert -out public.pem
		openssl rsa -inform PVK -outform PEM -in $file -out private.pem
		#writing RSA key
		name=$(basename $cert) 

		openssl pkcs12 -in public.pem -inkey private.pem -password pass:12345 -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ${name::-4}.pfx
		rm -f public.pem 
		rm -f private.pem
		echo ${name::-4}
		break
	fi	
done

}

for cert in DER/*
do
	pub=$(openssl x509 -inform DER -modulus -noout -in $cert)
	#echo $pub
	lookfor $pub
	
done


