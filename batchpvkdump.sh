#!/bin/bash

SID='S-1-5-21-2645140126-3212403647-2139448272-1001'
FILE="./Crypto/RSA/${SID}/*"
OUTDIR='./PVK/'
for file in $FILE 
do
	python cert_dpapi.py -m=Protect/$SID/ --sid $SID --nopass -f=$file -o $OUTDIR$(basename $file).pem
	#outfile=$(basename $file)
	#dd if=$file of=$OUTDIR$outfile.der bs=1 skip=$offset

done
