#!/bin/sh

TARCRYPT=tarcrypt.sh
TC=""
FAIL=0

fail ()
{
    FAIL=1
    echo "FAIL: $1" >&2
}

fatal ()
{
    echo "FATAL: $1" >&2
    exit 1
}

[ -f $TARCRYPT ] || fatal "Could not find tarcrypt script in this directory!"
[ -x $TARCRYPT ] || fatal "tarcrypt script is not exectuable!"

# get absolute path to tarcrypt executable
TC=$(readlink -f $TARCRYPT)

[ -n "$TC" ] || fatal "Could not get absolute path of tarcrypt file"

TEMP_DIR=$(mktemp)

TEST_STR1="A Test String"
TEST_STR2="A Second test string that is a little longer"

rm -rf $TEMP_DIR 
mkdir -p $TEMP_DIR

cd $TEMP_DIR

echo "$TEST_STR1" > t1.txt
echo "$TEST_STR2" > t2.txt

[ -f t1.txt ] || fail "Could not create t1.txt"
[ -f t2.txt ] || fail "Could not create t2.txt"

[ "$(cat t1.txt)" = "$TEST_STR1" ] || fail "t1.txt file contents not correct before encryption"
[ "$(cat t2.txt)" = "$TEST_STR2" ] || fail "t2.txt file contents not correct before encryption"

$TC -h

# clean-up and exit
rm -rf $TEMP_DIR

if (( FAIL )); then
    echo "Test Failed!"
    exit 1
else
    echo "Test Passed"
    exit 0
fi

