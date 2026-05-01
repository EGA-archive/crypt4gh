_crypt4gh() {
    local cmd cur prev
    cmd=$1
    cur=$2
    prev=$3

    # We check the previous word and potentially already conclude
    case "$prev" in
        crypt4gh)
            COMPREPLY=( $(compgen -W '-h --help -v --version --log encrypt decrypt rearrange reencrypt' -- "$cur") )
            compopt +o filenames +o dirnames  # Disable file/directory completion
            return
            ;;
        -h|--help|-v|--version) # No more suggestions
            COMPREPLY=()
            compopt +o filenames +o dirnames  
            return
            ;;
        --log|--sk|--recipient_pk|--header|"<"|">"|"<*"|">*")
            COMPREPLY=( $(compgen -f -- "$cur") )  # Enable filename completion
            return
	    ;;
	# In the following cases, we know what to suggest
        encrypt)
            COMPREPLY=( $(compgen -W '--sk --recipient_pk --range --header' -- "$cur") )
            return
            ;;
        decrypt)
            COMPREPLY=( $(compgen -W '--sk --sender_pk --range' -- "$cur") )
            return
            ;;
        rearrange)
            COMPREPLY=( $(compgen -W '--sk --range' -- "$cur") )
            return
            ;;
        reencrypt)
            COMPREPLY=( $(compgen -W '--sk --recipient_pk -t --trim --header-only' -- "$cur") )
            return
            ;;
    esac

    # If $prev is a filename, find the subcommand in the command line
    local subcommand=""
    for ((i=1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            -h|--help|-v|--version) # Skip --options with no arguments
                continue
                ;;
            --log|--sk|--recipient_pk|--header|"<"|">")
                # Skip the next word (filename) after these options
                i=$((i + 1))
                continue
                ;;
            -*) # Skip other options (no arguments)
                continue
                ;;
            encrypt|decrypt|rearrange|reencrypt)
                # Found a valid subcommand
                subcommand="${COMP_WORDS[i]}"
                break
                ;;
            *) # Skip unknown words
                continue
                ;;
        esac
    done

    case "$subcommand" in
        encrypt)
            COMPREPLY=( $(compgen -W '--sk --recipient_pk --range --header' -- "$cur") )
            ;;
        decrypt)
            COMPREPLY=( $(compgen -W '--sk --sender_pk --range' -- "$cur") )
            ;;
        rearrange)
            COMPREPLY=( $(compgen -W '--sk --range' -- "$cur") )
            ;;
        reencrypt)
            COMPREPLY=( $(compgen -W '--sk --recipient_pk -t --trim --header-only' -- "$cur") )
            ;;
	*) # No subcommand found or unknown subcommand: no completion
            COMPREPLY=()
	    # echo "" >&2
	    # echo "Unknown subcommand $subcommand" >&2
            ;;
    esac
}

complete -F _crypt4gh crypt4gh
