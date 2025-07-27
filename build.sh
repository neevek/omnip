#!/bin/bash

# npm install -g typescript
# npm install react react-dom
# npm install --save-dev @types/react @types/react-dom

pushd src/omnip-web
npm run build
popd
cargo build --release
