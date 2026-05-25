
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

@test "Bob sends a secret (random) 10MB file to Alice, over a URL" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    crypt4gh encrypt -2 --passphrase-from-env BOB_PASSPHRASE \
    	     	     	--sk ${BOB_SECKEY} \
			--recipient-pk ${ALICE_PUBKEY} \
			--header $TESTFILES/random.10MB.header.c4gh \
			--link "file://$TESTFILES/random.10MB.payload.c4gh" \
			< $TESTFILES/random.10MB \
			> $TESTFILES/random.10MB.payload.c4gh

    # Alice decrypts it
    crypt4gh decrypt --passphrase-from-env ALICE_PASSPHRASE \
    	     	     --sk ${ALICE_SECKEY} \
		     < $TESTFILES/random.10MB.header.c4gh \
		     > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]
}
