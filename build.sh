#!/bin/bash

pushd src/rsproxy-web
npm run build
popd
cargo build
