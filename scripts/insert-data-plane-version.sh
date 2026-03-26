#!/bin/sh
pattern="s/0.0.0-dev/$1/"
sed -i -e "$pattern" ./crates/data-plane/Cargo.toml