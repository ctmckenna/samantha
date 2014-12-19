#!/bin/bash

script=$(pwd)/${BASH_SOURCE[0]}
scriptdir=`dirname $script`

function apt_get() {
    sudo apt-get install $1
}

function start_with_cron() {
    local tmpfile=`mktemp ./temp.XXXXXX`
    local schedule="* * * * *"
    local script_exe="$scriptdir/cron_client_start.sh"
    (
        cat <<EOF
 `crontab -l | grep -v "$(basename $script)"`
$schedule $script start
EOF
    ) > $tmpfile
    crontab $tmpfile
    unlink $tmpfile
}

function start() {
    running=$(ps -ef | grep $scriptdir | grep python | grep -v grep | wc -l)
    if [ $running -eq 0 ]; then
        $scriptdir/main.py
    fi
}

function install() {
    sudo apt-get update
    apt_get python-pip
    apt_get python-dev

    sudo pip install websocket

    start_with_cron
}


case $1 in
    start)
        start
        ;;
    *)
        install