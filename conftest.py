#!/usr/bin/env python

import pytest
from pytest_mongo import factories

mongo_proc = factories.mongo_proc(port=None, logsdir='/tmp')
mongo = factories.mongodb('mongo_proc')

def pytest_addoption(parser):
    parser.addoption("--config", action="store", help="cacus config")

@pytest.fixture
def cacus(request, mongo):
    m = __import__('cacus')
    m.common.initialize(request.config.option.config, mongo=mongo)
    return m

