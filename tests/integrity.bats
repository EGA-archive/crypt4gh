#!/usr/bin/env bats

load _common/helpers

function setup() {

    # Defining the TMP dir
    TESTFILES=${BATS_TEST_FILENAME}.d
    mkdir -p "$TESTFILES"

}

function teardown() {
    rm -rf ${TESTFILES}
}

@test "Bob sends a secret file to Alice, who detects it is truncated" {

    TESTFILE=$TESTFILES/testfile

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=65536 count=10 of=$TESTFILE
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILE.c4gh

    # Remove the last empty segment, and the segment before that
    # truncate --size=$(( 132 + 65536 * 9 + (28 * 9) )) $TESTFILE.c4gh
    dd if=$TESTFILE.c4gh bs=590208 count=1 of=$TESTFILE.shorter.c4gh 2>/dev/null

    # Alice decrypts it, and notices it's truncated
    run \
    bash -c "crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
           	              --sk ${ALICE_SECKEY} \
		              < $TESTFILE.shorter.c4gh \
		              > $TESTFILE.received"
    [ "$status" -ne 0 ]

    run diff $TESTFILE $TESTFILE.received
    [ "$status" -ne 0 ]
}

@test "Bob sends a secret file to Alice, who can detect it is truncated" {

    TESTFILE=$TESTFILES/testfile.2

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=65536 count=10 of=$TESTFILE
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILE.c4gh

    # Remove only the last empty segment
    # truncate --size=$(( 132 + 65536 * 10 + (28 * 10) )) $TESTFILE.c4gh
    dd if=$TESTFILE.c4gh bs=655772 count=1 of=$TESTFILE.shorter.c4gh

    # Alice decrypts it, and notices it's truncated
    run \
    bash -c "crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
           	              --sk ${ALICE_SECKEY} \
		              < $TESTFILE.shorter.c4gh \
		              > $TESTFILE.received"
    [ "$status" -ne 0 ]

    run diff $TESTFILE $TESTFILE.received
    [ "$status" -eq 0 ]
}
