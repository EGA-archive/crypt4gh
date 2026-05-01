_crypt4gh_keygen() {
    local cmd cur prev
    cmd=$1
    cur=$2
    prev=$3

    # We check the previous word and potentially already conclude
    case "$prev" in
        crypt4gh-keygen)
            COMPREPLY=( $(compgen -W '-h --help -v --version --log -f --pk --sk --nocrypt -C --relock' -- "$cur") )
            compopt +o filenames +o dirnames  # Disable file/directory completion
            ;;
        -h|--help|-v|--version|-C) # No more suggestions
            COMPREPLY=()
            compopt +o filenames +o dirnames  
            ;;
        --log|--sk|--pk)
            COMPREPLY=( $(compgen -f -- "$cur") )  # Enable filename completion
	    ;;
	*)
            COMPREPLY=( $(compgen -W '-f --pk --sk --nocrypt -C --relock' -- "$cur") )
	    ;;
    esac

}

complete -F _crypt4gh_keygen crypt4gh-keygen
