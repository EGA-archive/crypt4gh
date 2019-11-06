
_crypt4ghkeygen()
{
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD -ge 1 ]; then
        COMPREPLY=( $( compgen -W '-h --help -v --version --log= -f --pk= --sk= --nocrypt -C= ' -- $cur) )
    fi
}

complete -o bashdefault -o default -o filenames -F _crypt4ghkeygen crypt4gh-keygen