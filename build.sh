#!/bin/bash

pushd src/omnip-web
npm run build
popd
cargo build --release
