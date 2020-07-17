#!/usr/bin/env bash

SCRIPT_NAME=$(basename "$0")
SCRIPTS_DIR=$(dirname "$0")

TOOL_NAMES=(push-all pull-all merge-forward list-tor-branches resquash)

function usage()
{
    echo "$SCRIPT_NAME [-h] [-n] [-v] [-f] <all|hooks|tools|aliases>"
    echo
    echo "  flags:"
    echo "    -h: show this help text"
    echo "    -n: dry-run"
    echo "    -v: verbose mode"
    echo "    -f: force-install even if \$TOR_DEVTOOLS_DIR looks fishy"
    echo
    echo "  modes:"
    echo "    hooks:   install git hooks in this repository."
    echo "    tools:   install scripts in \$TOR_DEVTOOLS_DIR"
    echo "    aliases: set up global git aliases for git tools in \$TOR_DEVTOOLS_DIR"
    echo "    all:     all of the above."
}

INSTALL_HOOKS=0
INSTALL_TOOLS=0
INSTALL_ALIASES=0

DRY_RUN=0
VERBOSE=0
FORCE=0

while getopts "hnfv" opt; do
    case "$opt" in
        h) usage
           exit 0
           ;;
        n) DRY_RUN=1
           ;;
        v) VERBOSE=1
           ;;
        f) FORCE=1
           ;;
        *) echo
           usage
           exit 1
           ;;
    esac
done

for item in "${@:$OPTIND}"; do
    case "$item" in
        hooks) INSTALL_HOOKS=1
               ;;
        tools) INSTALL_TOOLS=1
               ;;
        aliases) INSTALL_ALIASES=1
                 ;;
        all) INSTALL_HOOKS=1
             INSTALL_TOOLS=1
             INSTALL_ALIASES=1
             ;;
        *) echo "Unrecognized mode '$item'"
           usage
           exit 1
           ;;
    esac
done

if [[ $VERBOSE = 1 ]]; then
    function note()
    {
        echo "$@"
    }
else
    function note()
    {
        true
    }
fi

function fail()
{
    echo "$@" 1>&2
    exit 1
}

if [[ $INSTALL_HOOKS = 0 && $INSTALL_TOOLS = 0 && $INSTALL_ALIASES = 0 ]]; then
   echo "Nothing to do. Try $SCRIPT_NAME -h for a list of commands."
   exit 0
fi

if [[ $INSTALL_TOOLS = 1 || $INSTALL_ALIASES = 1 ]]; then
    if [[ -z "$TOR_DEVTOOLS_DIR" ]] ; then
        fail "\$TOR_DEVTOOLS_DIR was not set."
    fi
    note "Checking whether \$TOR_DEVTOOLS_DIR ($TOR_DEVTOOLS_DIR) is a git repo..."
    GITDIR=$(cd "$TOR_DEVTOOLS_DIR" && git rev-parse --git-dir 2>/dev/null)
    note "GITDIR is $GITDIR"
    if [[ -n "$GITDIR" ]] ; then
        cat <<EOF
You have asked me to install to \$TOR_DEVTOOLS_DIR ($TOR_DEVTOOLS_DIR).
That is inside a git repository, so you might not want to install there:
depending on what you pull or push, you might find yourself giving somebody
else write access to your scripts.  I think you should just use ~/bin or
something.
EOF

        echo
        if [[ "$FORCE" = 1 ]] ; then
            echo "I will install anyway, since you said '-f'."
        else
            echo "I will not install. You can tell me -f if you are really sure."
            exit 1
        fi
    else
        note "It was not."
    fi
fi

if [[ ! -d "$SCRIPTS_DIR" || ! -e "$SCRIPTS_DIR/git-push-all.sh" ]]; then
    fail "Couldn't find scripts in '$SCRIPTS_DIR'"
fi

if [[ $DRY_RUN = 1 ]]; then
    echo "** DRY RUN **"
    RUN="echo >>"
else
    RUN=
fi

set -e

# ======================================================================
if [[ $INSTALL_HOOKS = 1 ]]; then
       HOOKS_DIR=$(git rev-parse --git-path hooks)

       note "Looking for hooks directory"

       if [[ -z "$HOOKS_DIR" || ! -d "$HOOKS_DIR" ]]; then
           fail "Couldn't find git hooks directory."
       fi

       note "Found hooks directory in $HOOKS_DIR"

       note "Installing hooks"
       for fn in "$SCRIPTS_DIR"/*.git-hook; do
           name=$(basename "$fn")
           $RUN install -b "$fn" "${HOOKS_DIR}/${name%.git-hook}"
       done
fi


# ======================================================================
if [[ $INSTALL_TOOLS = 1 ]]; then
    note "Installing tools."
    note "Looking for \$TOR_DEVTOOLS_DIR ($TOR_DEVTOOLS_DIR)"

    if [[ ! -d "$TOR_DEVTOOLS_DIR" ]]; then
        note "Creating directory"
        $RUN mkdir -p "$TOR_DEVTOOLS_DIR"
    fi

    note "Copying scripts"
    for tool in "${TOOL_NAMES[@]}"; do
        $RUN install -b "${SCRIPTS_DIR}/git-${tool}.sh" "${TOR_DEVTOOLS_DIR}/"
    done
fi

# ======================================================================
if [[ $INSTALL_ALIASES = 1 ]]; then
    note "Installing aliases."
    note "Looking for \$TOR_DEVTOOLS_DIR ($TOR_DEVTOOLS_DIR)"

    note "Checking for ${TOR_DEVTOOLS_DIR}/git-push-all.sh"
    if [[ ! -x "${TOR_DEVTOOLS_DIR}/git-push-all.sh" ]]; then
        if [[ $DRY_RUN = 0 ]]; then
            fail "Could not find scripts in \$TOR_DEVTOOLS_DIR"
        fi
    fi

    note "Setting aliases"
    for tool in "${TOOL_NAMES[@]}"; do
        $RUN git config --global "alias.$tool" \!"${TOR_DEVTOOLS_DIR}/git-${tool}.sh"
    done

fi

note Done.
