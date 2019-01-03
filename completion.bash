#!/bin/env bash

_crypt4gh()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $( compgen -W '-h --help -v --version --log= encrypt decrypt reencrypt generate' -- $cur) )
    else
        case ${COMP_WORDS[1]} in
            encrypt)
            _crypt4gh_encrypt
        ;;
            decrypt)
            _crypt4gh_decrypt
        ;;
            reencrypt)
            _crypt4gh_reencrypt
        ;;
            generate)
            _crypt4gh_generate
        ;;
        esac

    fi
}

_crypt4gh_encrypt()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--sk= --recipient_pk= ' -- $cur) )
    fi
}

_crypt4gh_decrypt()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--sk= --sender_pk= --range= ' -- $cur) )
    fi
}

_crypt4gh_reencrypt()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -fW '--sk= --recipient_pk= --sender_public_key ' -- $cur) )
    fi
}

_crypt4gh_generate()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '-f --pk= --sk= --nocrypt -C= -R= ' -- $cur) )
    fi
}

complete -o bashdefault -o default -o filenames -F _crypt4gh crypt4gh

