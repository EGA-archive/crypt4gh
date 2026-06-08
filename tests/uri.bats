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

@test "Bob sends the testfile secretly to Alice, via payload URI" {

    TESTFILE=$TESTFILES/testfile

    # Generate a random "4-segments" file, and keep it
    run dd if=/dev/urandom bs=262144 count=1 of=$TESTFILE
    [ "$status" -eq 0 ]

    # Bob encrypts the testfile for Alice, storing the header separately
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${ALICE_PUBKEY} \
		     --header $TESTFILES/header.alice.c4gh \
		     --link "file://$TESTFILE.data.c4gh" \
		     < $TESTFILE \
		     > $TESTFILE.data.c4gh

     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILE.received

    run diff $TESTFILE $TESTFILE.received
    [ "$status" -eq 0 ]
}

@test "Bob sends the testfile secretly to himself and Alice, via payload URI" {

    TESTFILE=$TESTFILES/testfile.2

    # Generate a random "4-segments" file, and keep it
    run dd if=/dev/urandom bs=262144 count=1 of=$TESTFILE
    [ "$status" -eq 0 ]

    # Bob encrypts the testfile for himself,
    # storing the header separately,
    # and pointing paylod to URI
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${BOB_PUBKEY} \
		     --header $TESTFILES/header.bob.c4gh \
		     < $TESTFILE \
		     > $TESTFILE.payload.c4gh

     # Bob reencrypt for  the resulting header, and fetches the payload
     crypt4gh reencrypt -2 \
                       --passphrase-from-env BOB_PASSPHRASE \
                       --sk ${BOB_SECKEY} \
    	     	       --recipient-pk ${ALICE_PUBKEY} \
		       --header-only \
		       --link "file://$TESTFILE.payload.c4gh" \
		       < $TESTFILES/header.bob.c4gh \
		       > $TESTFILES/header.alice.c4gh


     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILE.received

    run diff $TESTFILE $TESTFILE.received
    [ "$status" -eq 0 ]
}

@test "Bob sends the testfile secretly to himself and Alice, via new payload URI" {

    TESTFILE=$TESTFILES/testfile.3

    # Generate a random "4-segments" file, and keep it
    run dd if=/dev/urandom bs=262144 count=1 of=$TESTFILE
    [ "$status" -eq 0 ]

    # Bob encrypts the testfile for himself,
    # storing the header separately,
    # and pointing paylod to new URI
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${BOB_PUBKEY} \
		     --header $TESTFILES/header.bob.c4gh \
		     < $TESTFILE \
		     > $TESTFILE.payload.c4gh

     mv $TESTFILE.payload.c4gh $TESTFILE.payload.new.c4gh

     # Bob reencrypt for  the resulting header, and fetches the payload
     crypt4gh reencrypt -2 \
                       --passphrase-from-env BOB_PASSPHRASE \
                       --sk ${BOB_SECKEY} \
    	     	       --recipient-pk ${ALICE_PUBKEY} \
		       --header-only \
		       --link "file://$TESTFILE.payload.new.c4gh" \
		       < $TESTFILES/header.bob.c4gh \
		       > $TESTFILES/header.alice.c4gh

     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILE.received

    run diff $TESTFILE $TESTFILE.received
    [ "$status" -eq 0 ]
}
