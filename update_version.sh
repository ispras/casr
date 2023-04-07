#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo Usage: $0 old_version new_version
    echo Example: $0 1.2.0 1.3.0
fi

sed -i "s/version = \"$1\"/version = \"$2\"/g" Cargo.toml
sed -i "s/version = \"$1\"/version = \"$2\"/g" casr/Cargo.toml
sed -i "s/version = \"$1\"/version = \"$2\"/g" libcasr/Cargo.toml
