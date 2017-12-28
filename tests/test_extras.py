#!/usr/bin/env python

from cacus import extras


def test_DebVersion():
    assert extras.DebVersion('1.0') < extras.DebVersion('2.0')
    assert extras.DebVersion('1.0') == extras.DebVersion('1.0')
    assert extras.DebVersion('1.0') == extras.DebVersion('0:1.0')
    assert extras.DebVersion('1:1.0') >= extras.DebVersion('2.0')
    assert extras.DebVersion('1:1.0') >= extras.DebVersion('1:1.0')
    assert extras.DebVersion('1.0') < extras.DebVersion('1.0-1')
    assert extras.DebVersion('1.0-10') > extras.DebVersion('1.0-1')
    assert extras.DebVersion('1.0-10~~pre') < extras.DebVersion('1.0-10')
    assert extras.DebVersion('1.0-10~~pre') > extras.DebVersion('1.0-10~~~pre')
    assert extras.DebVersion('1.0-deb9u2') > extras.DebVersion('1.0-deb9u1')
