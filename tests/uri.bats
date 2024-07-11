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

@test "Bob sends the testfile secretly to Alice over an URI" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --recipient_pk ${ALICE_PUBKEY} --uri "file://$TESTFILES/message.c4gh.payload" --header "$TESTFILES/message.c4gh.header" < $TESTFILE > $TESTFILES/message.c4gh.payload

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.c4gh.header > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}
