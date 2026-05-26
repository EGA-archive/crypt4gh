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

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice, storing the header separately
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${ALICE_PUBKEY} \
		     --header $TESTFILES/header.alice.c4gh \
		     --link $TESTFILES/data.c4gh \
		     < $TESTFILE \
		     > $TESTFILES/data.c4gh

     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}

@test "Bob sends the testfile secretly to himself and Alice, via payload URI" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself,
    # storing the header separately,
    # and pointing paylod to URI
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${BOB_PUBKEY} \
		     --header $TESTFILES/header.bob.c4gh \
		     --link "$TESTFILES/data.c4gh" \
		     < $TESTFILE \
		     > $TESTFILES/data.c4gh

     # Bob reencrypt for  the resulting header, and fetches the payload
     crypt4gh reencrypt -2 \
                       --passphrase-from-env BOB_PASSPHRASE \
                       --sk ${BOB_SECKEY} \
		       --header-only \
		       < $TESTFILES/header.bob.c4gh \
		       > $TESTFILES/header.alice.c4gh

     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}

@test "Bob sends the testfile secretly to himself and Alice, via new payload URI" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself,
    # storing the header separately,
    # and pointing paylod to new URI
    crypt4gh encrypt -2 \
                     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${BOB_PUBKEY} \
		     --header $TESTFILES/header.bob.c4gh \
		     --link "$TESTFILES/data.c4gh" \
		     < $TESTFILE \
		     > $TESTFILES/data.c4gh

     mv $TESTFILES/data.c4gh $TESTFILES/data.new.c4gh

     # Bob reencrypt for  the resulting header, and fetches the payload
     crypt4gh reencrypt -2 \
                       --passphrase-from-env BOB_PASSPHRASE \
                       --sk ${BOB_SECKEY} \
		       --header-only \
		       --link "$TESTFILES/data.new.c4gh" \
		       < $TESTFILES/header.bob.c4gh \
		       > $TESTFILES/header.alice.c4gh

     # Alice decrypts the resulting header, and fetches the payload
     crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                      --sk ${ALICE_SECKEY} \
		      < $TESTFILES/header.alice.c4gh \
		      > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}
