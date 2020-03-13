
_crypt4gh()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $( compgen -W '-h --help -v --version --log= -h --help -v --version --log= -h --help -v --version --log= -h --help -v --version --log= encrypt decrypt rearrange reencrypt' -- $cur) )
    else
        case ${COMP_WORDS[1]} in
            encrypt)
            _crypt4gh_encrypt
        ;;
            decrypt)
            _crypt4gh_decrypt
        ;;
            rearrange)
            _crypt4gh_rearrange
        ;;
            reencrypt)
            _crypt4gh_reencrypt
        ;;
        esac

    fi
}

_crypt4gh_encrypt()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--sk= --recipient_pk= --recipient_pk= --range= ' -- $cur) )
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

_crypt4gh_rearrange()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--sk= --range= ' -- $cur) )
    fi
}

_crypt4gh_reencrypt()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 2 ]; then
        COMPREPLY=( $( compgen -W '--sk= --recipient_pk= --recipient_pk= -t --trim ' -- $cur) )
    fi
}

complete -o bashdefault -o default -o filenames -F _crypt4gh crypt4gh