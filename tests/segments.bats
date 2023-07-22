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


@test "Bob sends only the Bs from the testfile secretly to Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd

    # Bob encrypts the testfile for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} --range 65536-131073 -n < $TESTFILE > $TESTFILES/message.b.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.b.c4gh > $TESTFILES/message.b.received

    # We count 65536 characters
    run wc -c $TESTFILES/message.b.received
    count=$(awk '{ print $1 }' <<<"$output")
    [ "$count" -eq 65536 ]

    # All of them are b (well, we check if we find another character than b)
    run grep -v b $TESTFILES/message.b.received
    [ "$status" -eq 1 ]

    unset C4GH_PASSPHRASE
}

@test "Bob sends one A, all Bs, one C, from the testfile secretly to Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd
    MESSAGEFILE=${BATS_TEST_DIRNAME}/_common/testfile.abbbc
    
    # Bob encrypts the testfile for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} --range 65535-131074 -n < $TESTFILE > $TESTFILES/message.abbbc.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.abbbc.c4gh > $TESTFILES/message.abbbc.received

    run diff $MESSAGEFILE $TESTFILES/message.abbbc.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}

@test "Bob rearranges the encrypted testfile to send one A, all Bs, one C, to Alice" {

    TESTFILE=${BATS_TEST_DIRNAME}/_common/testfile.abcd
    MESSAGEFILE=${BATS_TEST_DIRNAME}/_common/testfile.abbbc
    
    # Bob encrypts the testfile for himself
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk ${BOB_PUBKEY} -n < $TESTFILE > $TESTFILES/message.bob.c4gh

    # Bob rearranges it
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh rearrange --sk ${BOB_SECKEY} --range 65535-131074 < $TESTFILES/message.bob.c4gh > $TESTFILES/message.bob.abbbc.c4gh

    # Bob reencrypts it for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh reencrypt --sk ${BOB_SECKEY} --recipient_pk ${ALICE_PUBKEY} < $TESTFILES/message.bob.abbbc.c4gh > $TESTFILES/message.abbbc.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/message.abbbc.c4gh > $TESTFILES/message.abbbc.received

    run diff $MESSAGEFILE $TESTFILES/message.abbbc.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}
