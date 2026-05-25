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

@test "Bob sends the testfile secretly to himself and Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${BOB_PUBKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILES/message.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]

    # Bob decrypts it
    crypt4gh decrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.bob.received

    run diff $TESTFILE $TESTFILES/message.bob.received
    [ "$status" -eq 0 ]
}

@test "Bob encrypts the testfile for himself and reencrypts it for himself and Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${BOB_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILES/message.bob.c4gh

    # Bob changes the header for Alice and Tom
    crypt4gh reencrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	       --sk ${BOB_SECKEY} \
		       --recipient-pk ${BOB_PUBKEY} \
		       --recipient-pk ${ALICE_PUBKEY} \
		       < $TESTFILES/message.bob.c4gh \
		       > $TESTFILES/message.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]

    # Bob decrypts it
    crypt4gh decrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.bob.received

    run diff $TESTFILE $TESTFILES/message.bob.received
    [ "$status" -eq 0 ]
}
