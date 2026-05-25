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

@test "Bob sends a secret (random) 10MB file to Alice" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     < $TESTFILES/random.10MB \
		     > $TESTFILES/random.10MB.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/random.10MB.c4gh \
		     > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]
}

@test "Bob sends the testfile secretly to Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILES/message.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}

@test "Bob encrypts the testfile for himself and reencrypts it for Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself
    crypt4gh encrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${BOB_PUBKEY} \
		     < $TESTFILE \
		     > $TESTFILES/message.bob.c4gh

    # Bob changes the header for Alice
    crypt4gh reencrypt --passphrase-from-env BOB_PASSPHRASE \
    	     	       --sk ${BOB_SECKEY} \
		       --recipient-pk ${ALICE_PUBKEY} \
		       < $TESTFILES/message.bob.c4gh \
		       > $TESTFILES/message.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/message.c4gh \
		     > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]
}

@test "Bob sends a secret (random) 10MB file to Alice, without his key" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice, without a key
    crypt4gh encrypt --recipient-pk ${ALICE_PUBKEY} \
    	     	     < $TESTFILES/random.10MB \
		     > $TESTFILES/random.10MB.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/random.10MB.c4gh \
		     > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]
}
