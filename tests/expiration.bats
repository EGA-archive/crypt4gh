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

@test "Bob sends the testfile secretly to Alice, with a past expiration date" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    EXP_DATE=$(date -Iseconds -jf %s $(( $(date +%s) - 86400 * 2 )))
    crypt4gh encrypt --recipient_pk ${ALICE_PUBKEY} --expiration "${EXP_DATE}" < $TESTFILE > $TESTFILES/message.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    run --separate-stderr crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.c4gh

    [[ "$stderr" =~ "Expired on" ]]

    unset C4GH_PASSPHRASE
}

@test "Bob sends the testfile secretly to Alice, with a future expiration date" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    EXP_DATE=$(date -Iseconds -jf %s $(( $(date +%s) + 86400 * 2 )))
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} --expiration "${EXP_DATE}" < $TESTFILE > $TESTFILES/message.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.c4gh > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]


    unset C4GH_PASSPHRASE
}
