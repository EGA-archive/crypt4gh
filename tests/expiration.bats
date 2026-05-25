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

@test "Bob sends a file to Alice, with expiration (1h) " {

    # Generate a random 100 KB file, and keep it
    run dd if=/dev/urandom bs=1024 count=100 of=$TESTFILES/random.100KB
    [ "$status" -eq 0 ]

    # Now + 3600 seconds
    # run python ${BATS_TEST_DIRNAME}/_common/date.py 3600
    # expiration="${lines[0]}"
    expiration=$(python ${BATS_TEST_DIRNAME}/_common/date.py 3600)

    # Bob encrypts it for Alice, with expiration
    crypt4gh encrypt -2 \
    	     	     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     --expiration "${expiration}" \
		     < $TESTFILES/random.100KB \
		     > $TESTFILES/random.100KB.c4gh

    # Alice waits 3 seconds
    sleep 3

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/random.100KB.c4gh \
		     > $TESTFILES/random.100KB.received

    run diff $TESTFILES/random.100KB $TESTFILES/random.100KB.received
    [ "$status" -eq 0 ]
}

@test "Bob sends a file to Alice, which expires after 3 seconds" {

    bats_require_minimum_version 1.5.0

    # Generate a random 10 KB file, and keep it
    run dd if=/dev/urandom bs=1024 count=100 of=$TESTFILES/random.100KB.2
    [ "$status" -eq 0 ]

    # Now + 3 seconds
    # run python ${BATS_TEST_DIRNAME}/_common/date.py +3
    # expiration="${lines[0]}"
    expiration=$(python ${BATS_TEST_DIRNAME}/_common/date.py +3)

    # Bob encrypts it for Alice, with expiration
    crypt4gh encrypt -2 \
    	     	     --passphrase-from-env BOB_PASSPHRASE \
    	     	     --sk ${BOB_SECKEY} \
		     --recipient-pk ${ALICE_PUBKEY} \
		     --expiration "${expiration}" \
		     < $TESTFILES/random.100KB.2 \
		     > $TESTFILES/random.100KB.2.c4gh

    # Alice can decrypt it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/random.100KB.2.c4gh \
		     > $TESTFILES/random.100KB.2.received

    run diff $TESTFILES/random.100KB.2 $TESTFILES/random.100KB.2.received
    [ "$status" -eq 0 ]

    # Alice waits 5 seconds
    sleep 5

    # Alice decrypts it, too late
    run -1 --separate-stderr \
    bash -c "crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
           	              --sk ${ALICE_SECKEY} \
		              < $TESTFILES/random.100KB.2.c4gh \
		              > $TESTFILES/random.100KB.2.received.expired"

    # Latest stderr line should contain "Expired"
    [[ "${stderr_lines[-1]}" =~ .*Expired.* ]]

    run diff $TESTFILES/random.100KB.2 $TESTFILES/random.100KB.2.received.expired
    [ "$status" -ne 0 ]
}
