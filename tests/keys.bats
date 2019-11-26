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

@test "Bob sends a secret (random) 10MB file to Alice, using its ssh-key" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    rm -f $TESTFILES/bob.sshkey{,.pub}

    # Bob creates an ssh-key (OpenSSH 6.5+)
    run ssh-keygen -t ed25519 -f $TESTFILES/bob.sshkey -N "${BOB_PASSPHRASE}"
    # Yeah, same passphrase, not very good, but good enough
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk $TESTFILES/bob.sshkey --recipient_pk ${ALICE_PUBKEY} < $TESTFILES/random.10MB > $TESTFILES/random.10MB.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk ${ALICE_SECKEY} < $TESTFILES/random.10MB.c4gh > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}

@test "Bob sends a secret (random) 10MB file to Alice, using Alice's ssh-key" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    rm -f $TESTFILES/alice.sshkey{,.pub}

    # Bob creates an ssh-key (OpenSSH 6.5+)
    run ssh-keygen -t ed25519 -f $TESTFILES/alice.sshkey -N "${ALICE_PASSPHRASE}"
    # Yeah, same passphrase, not very good, but good enough
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk ${BOB_SECKEY} --recipient_pk $TESTFILES/alice.sshkey.pub < $TESTFILES/random.10MB > $TESTFILES/random.10MB.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk $TESTFILES/alice.sshkey < $TESTFILES/random.10MB.c4gh > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}

@test "Bob sends a secret (random) 10MB file to Alice, both using their ssh-keys" {

    # Generate a random 10 MB file, and keep it
    run dd if=/dev/urandom bs=1048576 count=10 of=$TESTFILES/random.10MB
    [ "$status" -eq 0 ]

    # Clean up
    rm -f $TESTFILES/{bob,alice}.sshkey{,.pub}

    # Bob and Alice creates an ssh-key (OpenSSH 6.5+)
    run ssh-keygen -t ed25519 -f $TESTFILES/bob.sshkey -N "${BOB_PASSPHRASE}"
    [ "$status" -eq 0 ]
    run ssh-keygen -t ed25519 -f $TESTFILES/alice.sshkey -N "${ALICE_PASSPHRASE}"
    # Yeah, same passphrase, not very good, but good enough
    [ "$status" -eq 0 ]

    # Bob encrypts it for Alice
    export C4GH_PASSPHRASE=${BOB_PASSPHRASE}
    crypt4gh encrypt --sk $TESTFILES/bob.sshkey --recipient_pk $TESTFILES/alice.sshkey.pub < $TESTFILES/random.10MB > $TESTFILES/random.10MB.c4gh

    # Alice decrypts it
    export C4GH_PASSPHRASE=${ALICE_PASSPHRASE}
    crypt4gh decrypt --sk $TESTFILES/alice.sshkey < $TESTFILES/random.10MB.c4gh > $TESTFILES/random.10MB.received

    run diff $TESTFILES/random.10MB $TESTFILES/random.10MB.received
    [ "$status" -eq 0 ]

    unset C4GH_PASSPHRASE
}
