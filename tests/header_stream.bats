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

@test "Bob sends the testfile secretly (with separate header and data) to Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice, storing the header separately
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
    	     	     --recipient-pk ${ALICE_PUBKEY} \
		     --header $TESTFILES/header.alice.c4gh \
		     < $TESTFILE \
		     > $TESTFILES/data.c4gh

     # Alice concatenates the header and the data and decrypts the combined result
    cat $TESTFILES/header.alice.c4gh $TESTFILES/data.c4gh | crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                     		     			    	             --sk ${ALICE_SECKEY} \
									     > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}

@test "Bob encrypts the testfile for himself (with separate header) and reencrypts the header for Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
                     --sk ${BOB_SECKEY} \
		     --recipient-pk ${BOB_PUBKEY} \
		     --header $TESTFILES/header.bob.c4gh \
		     < $TESTFILE \
		     > $TESTFILES/data.c4gh

    # Bob changes the header for Alice
    crypt4gh reencrypt --passphrase-from-env BOB_PASSPHRASE \
                       --sk ${BOB_SECKEY} \
                       --recipient-pk ${ALICE_PUBKEY} \
		       --header-only \
		       < $TESTFILES/header.bob.c4gh \
		       > $TESTFILES/header.alice.c4gh

    # Alice concatenates the header and data and decrypts the results
    cat $TESTFILES/header.alice.c4gh $TESTFILES/data.c4gh | crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
                     		     			    	     	     --sk ${ALICE_SECKEY} \
									     > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}
