#!/usr/bin/env python

import pytest

def pytest_addoption(parser):
    parser.addoption("--config", action="store", help="cacus config")


