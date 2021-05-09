#!/bin/bash

export CARGO_TARGET_DIR=$HOME/rust/tcp-rs/target

cargo build --release

ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/tcp
$CARGO_TARGET_DIR/release/tcp &
pid=$!
trap "kill $pid" SIGINT SIGTERM
wait $pid
