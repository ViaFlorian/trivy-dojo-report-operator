#!/usr/bin/env bash
set -e

sudo apt-get update
sudo apt install -y git-lfs

# if the .venv directory was mounted as a named volume, it needs the ownership changed
sudo chown vscode .venv || true

# make the python binary location predictable
poetry config virtualenvs.in-project true
poetry install --with=dev --no-root || true
