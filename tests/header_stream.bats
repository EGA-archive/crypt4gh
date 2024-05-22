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
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} --header $TESTFILES/header.alice.c4gh < $TESTFILE > $TESTFILES/data.c4gh

     # Alice concatenates the header and the data and decrypts the combined result
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    cat $TESTFILES/header.alice.c4gh $TESTFILES/data.c4gh | crypt4gh decrypt --sk ${ALICE_SECKEY} > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}

@test "Bob encrypts the testfile for himself (with separate header) and reencrypts the header for Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for himself
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${BOB_PUBKEY} --header $TESTFILES/header.bob.c4gh < $TESTFILE > $TESTFILES/data.c4gh

    # Bob changes the header for Alice
    crypt4gh reencrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} < $TESTFILES/header.bob.c4gh > $TESTFILES/header.alice.c4gh

    # Alice concatenates the header and data and decrypts the results
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    cat $TESTFILES/header.alice.c4gh $TESTFILES/data.c4gh | crypt4gh decrypt --sk ${ALICE_SECKEY} > $TESTFILES/message.received

    run diff $TESTFILE $TESTFILES/message.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}