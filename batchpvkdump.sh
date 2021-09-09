#!/bin/bash

FILE="./Crypto/RSA/S-1-5-21-3255726888-3229116256-1774431785-1002/*"
OUTDIR='./PVK/'
for file in $FILE 
do
	python cert_dpapi.py -m=Protect/S-1-5-21-3255726888-3229116256-1774431785-1002/ --sid S-1-5-21-3255726888-3229116256-1774431785-1002 --nopass -f=$file -o $OUTDIR$(basename $file).pem
	#outfile=$(basename $file)
	#dd if=$file of=$OUTDIR$outfile.der bs=1 skip=$offset

done
