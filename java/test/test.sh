#!/bin/bash

# Tests AESCrypt over the set of files in 'resources'.
# Generated files are stored in 'outputs'.

rm -f outputs/*

RESULTS=""
for RESOURCE in resources/*
do
	TEST=`basename $RESOURCE .dat`
	AES_OUT=outputs/$TEST.aes
	BAK_OUT=outputs/$TEST.dat
	RESULT="OK"

	echo -e "\nRunning test $TEST..."	
	java -cp ../bin es.vocali.util.AESCrypt e testpass $RESOURCE $AES_OUT
	java -cp ../bin es.vocali.util.AESCrypt d testpass $AES_OUT $BAK_OUT
	diff -q $RESOURCE $BAK_OUT > /dev/null
	[ $? -ne 0 ] && RESULT="ERROR"
	RESULTS+=`echo -e "\nTest $TEST result: $RESULT"`
done
echo -e "\n$RESULTS"
