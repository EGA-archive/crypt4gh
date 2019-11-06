#!/usr/bin/env bash

[ ${BASH_VERSINFO[0]} -lt 4 ] && echo 'Bash 4 (or higher) is required' 1>&2 && exit 1

HERE=$(dirname ${BASH_SOURCE[0]})

# These are already prepared keys
BOB_SECKEY=${HERE}/bob.sec
BOB_PUBKEY=${HERE}/bob.pub
ALICE_PUBKEY=${HERE}/alice.pub
ALICE_SECKEY=${HERE}/alice.sec

# Ya man, they're crazy
ALICE_PASSPHRASE=alice
BOB_PASSPHRASE=bob

# Convenience function to capture _all_ outputs
function c4gh_run {
    echo -e "+++ $@" >> ${BATS_TEST_FILENAME}.debug
    run "$@"
    echo -e "$output" >> ${BATS_TEST_FILENAME}.debug
    echo -e "--- Status: $status" >> ${BATS_TEST_FILENAME}.debug
}
