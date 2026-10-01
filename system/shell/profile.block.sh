# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi

# Created by `pipx` on 2026-03-08 08:39:43
export PATH="$PATH:{{ HOME }}/.local/bin"

export PATH="$HOME/.elan/bin:$PATH"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"


# Added by Antigravity CLI installer
export PATH="{{ HOME }}/.local/bin:$PATH"

# >>> gauss workflow installer env >>>
export GAUSS_HOME="${GAUSS_HOME:-{{ HOME }}/.gauss}"
export GAUSS_INSTALL_ROOT="${GAUSS_INSTALL_ROOT:-{{ HOME }}/OpenGauss}"
export PATH="$HOME/.local/bin:{{ HOME }}/OpenGauss/venv/bin:$HOME/.elan/bin:$PATH"
export PROMPT_TOOLKIT_NO_CPR=1
# <<< gauss workflow installer env <<<
export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"

# >>> ai-agents-skills credential lanes >>>
# Launch a credential-bearing AAS skill (compute lanes, ARL, remote-bridge,
# send-email, zotero senders) from the shared runtime under ~/.local.
# ai-agents-skills never uses root: since its owner-controlled launcher check
# (ai-agents-skills 3c40db2), run_skill.sh accepts a launcher that the owner
# owns and no group or other can write, so no root-owned copy is involved.
#
# Everything here is scoped to the subshell on purpose. Exporting
# AAS_COMPUTE_SECRETS_FILE into the ambient environment arms the credential
# contract for skills this does not target.
aas_compute() {
    local launcher="$HOME/.local/share/ai-agents-skills/runtime/run_skill.sh" ws
    if [ ! -x "$launcher" ]; then
        echo "aas_compute: the ai-agents-skills shared runtime is not installed" >&2
        return 1
    fi
    ws="${AAS_AUTOLOOP_COMPUTE_WORKSPACE:-$HOME/.openclaw/workspace}"
    (
        [ -d "$ws" ] && cd "$ws"
        [ -f "$HOME/.config/ai-agents-skills/compute.env" ] \
            && export AAS_COMPUTE_SECRETS_FILE="$HOME/.config/ai-agents-skills/compute.env"
        bash "$launcher" "$@"
    )
}
# <<< ai-agents-skills credential lanes <<<
