#!/bin/bash
WAPT_HOME="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
NCURSES_NO_UTF8_ACS=1 PYTHONHOME="${WAPT_HOME}" PYTHONPATH="${WAPT_HOME}"  "${WAPT_HOME}/bin/python" "${WAPT_HOME}"/wapt-get.py $@
