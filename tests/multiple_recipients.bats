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
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${BOB_PUBKEY} --recipient_pk ${ALICE_PUBKEY} < $TESTFILE > $TESTFILES/message.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.c4gh > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]

    # Bob decrypts it
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh decrypt --sk ${BOB_SECKEY} < $TESTFILES/message.c4gh > $TESTFILES/message.bob.received

    run diff $TESTFILE $TESTFILES/message.bob.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}

@test "Bob encrypts the testfile for himself and reencrypts it for himself and Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${BOB_PUBKEY} < $TESTFILE > $TESTFILES/message.bob.c4gh

    # Bob changes the header for Alice and Tom
    crypt4gh reencrypt --sk ${BOB_SECKEY} --recipient_pk ${BOB_PUBKEY} --recipient_pk ${ALICE_PUBKEY} < $TESTFILES/message.bob.c4gh > $TESTFILES/message.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.c4gh > $TESTFILES/message.alice.received

    run diff $TESTFILE $TESTFILES/message.alice.received
    [ "$status" -eq 0 ]

    # Tom decrypts it
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh decrypt --sk ${BOB_SECKEY} < $TESTFILES/message.c4gh > $TESTFILES/message.bob.received

    run diff $TESTFILE $TESTFILES/message.bob.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}
