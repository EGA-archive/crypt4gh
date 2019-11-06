
_crypt4ghdebug()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 1 ]; then
        COMPREPLY=( $( compgen -W '-h --help -v --version --log= --sk= --sender_pk= ' -- $cur) )
    fi
}

complete -o bashdefault -o default -o filenames -F _crypt4ghdebug crypt4gh-debug