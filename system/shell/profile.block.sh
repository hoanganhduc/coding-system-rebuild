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
_gauss_shell_autoenv=1
case "${BASH_EXECUTION_STRING:-}" in
  *".opengauss-template/runtime.env"*)
    _gauss_shell_autoenv=0
    ;;
esac
if [ "${OPEN_GAUSS_SKIP_SHELL_AUTOENV:-0}" = "1" ]; then
  _gauss_shell_autoenv=0
fi
if [ "$_gauss_shell_autoenv" = "1" ] && [ -f "$GAUSS_HOME/.env" ]; then
  set -a
  . "$GAUSS_HOME/.env"
  set +a
fi
unset _gauss_shell_autoenv
export PATH="$HOME/.local/bin:{{ HOME }}/OpenGauss/venv/bin:$HOME/.elan/bin:$PATH"
export PROMPT_TOOLKIT_NO_CPR=1
# <<< gauss workflow installer env <<<
export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"
