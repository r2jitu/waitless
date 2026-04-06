#!/bin/bash
# Regenerate rust-project.json for rust-analyzer.
# Run after adding/removing crates or changing deps.
exec bazel run //:rust_analyzer -- \
    //apps/webserver:app \
    //kernel \
    //drivers \
    //net \
    //uni
