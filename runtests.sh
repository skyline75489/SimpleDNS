#!/bin/sh
PYTHONPATH=.
export PYTHONPATH
pip install pytest pytest-cov
py.test --cov simpledns tests/
