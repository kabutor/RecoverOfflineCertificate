#!/bin/bash

FILE="./My/Certificates/*"
OUTDIR='./DER/'
for file in $FILE 
do
	offset=$(binwalk $file|grep 0x|awk '{print $1;exit}')
	outfile=$(basename $file)
	dd if=$file of=$OUTDIR$outfile.der bs=1 skip=$offset

done
