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

@test "Bob sends a secret message to Alice, buried in some random data" {

    # Original message
    echo -n "Let's have beers in the sauna! or Dinner at 7pm?" > $TESTFILES/message.bob

    # Bob encrypts a file for Alice, and tucks in an edit list. The skipped pieces are random data.
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    python ${BATS_TEST_DIRNAME}/_common/edit_list_gen.py ${BOB_SECKEY} ${ALICE_PUBKEY} > $TESTFILES/message.bob.c4gh <<EOF
Let's have
 beers 
in the sauna!
 or 
Dinner 
at 7pm?
EOF

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.bob.c4gh > $TESTFILES/message.alice

    run diff $TESTFILES/message.bob $TESTFILES/message.alice
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}
