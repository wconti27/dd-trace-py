#!/usr/bin/env python3

import pytest


try:
    from ddtrace.appsec.iast import oce
    from ddtrace.appsec.iast._taint_tracking.aspects import add_aspect
    from ddtrace.appsec.iast._taint_tracking import Source
    from ddtrace.appsec.iast._taint_tracking import OriginType
    from ddtrace.appsec.iast._taint_tracking import setup as taint_tracking_setup
    from ddtrace.appsec.iast._taint_tracking import taint_pyobject
    from ddtrace.appsec.iast._taint_tracking import taint_ranges_as_evidence_info
except (ImportError, AttributeError):
    pytest.skip("IAST not supported for this Python version", allow_module_level=True)


def setup():
    taint_tracking_setup(bytes.join, bytearray.join)
    oce._enabled = True


def test_taint_ranges_as_evidence_info_nothing_tainted():
    text = "nothing tainted"
    value_parts, sources = taint_ranges_as_evidence_info(text)
    assert value_parts == [{"value": text}]
    assert sources == []


def test_taint_ranges_as_evidence_info_all_tainted():
    arg = "all tainted"
    input_info = Source("request_body", arg)
    tainted_text = taint_pyobject(arg, input_info)
    value_parts, sources = taint_ranges_as_evidence_info(tainted_text)
    assert value_parts == [{"value": tainted_text, "source": 0}]
    assert sources == [input_info]


def test_taint_ranges_as_evidence_info_tainted_op1_add():
    arg = "tainted part"
    input_info = Source("request_body", arg)
    text = "|not tainted part|"
    tainted_text = taint_pyobject(arg, input_info)
    tainted_add_result = add_aspect(tainted_text, text)

    value_parts, sources = taint_ranges_as_evidence_info(tainted_add_result)
    assert value_parts == [{"value": tainted_text, "source": 0}, {"value": text}]
    assert sources == [input_info]


def test_taint_ranges_as_evidence_info_tainted_op2_add():
    arg = "tainted part"
    input_info = Source("request_body", arg)
    text = "|not tainted part|"
    tainted_text = taint_pyobject(arg, input_info)
    tainted_add_result = add_aspect(text, tainted_text)

    value_parts, sources = taint_ranges_as_evidence_info(tainted_add_result)
    assert value_parts == [{"value": text}, {"value": tainted_text, "source": 0}]
    assert sources == [input_info]


def test_taint_ranges_as_evidence_info_same_tainted_op1_and_op3_add():
    arg = "tainted part"
    input_info = Source("request_body", arg)
    text = "|not tainted part|"
    tainted_text = taint_pyobject(arg, input_info)
    tainted_add_result = add_aspect(tainted_text, add_aspect(text, tainted_text))

    value_parts, sources = taint_ranges_as_evidence_info(tainted_add_result)
    assert value_parts == [{"value": tainted_text, "source": 0}, {"value": text}, {"value": tainted_text, "source": 0}]
    assert sources == [input_info]


def test_taint_ranges_as_evidence_info_different_tainted_op1_and_op3_add():
    arg1 = "tainted body"
    arg2 = "tainted header"
    input_info1 = Source("request_body", arg1)
    input_info2 = Source("request_header", arg2)
    text = "|not tainted part|"
    tainted_text1 = taint_pyobject(arg1, input_info1)
    tainted_text2 = taint_pyobject(arg2, input_info2)
    tainted_add_result = add_aspect(tainted_text1, add_aspect(text, tainted_text2))

    value_parts, sources = taint_ranges_as_evidence_info(tainted_add_result)
    assert value_parts == [
        {"value": tainted_text1, "source": 0},
        {"value": text},
        {"value": tainted_text2, "source": 1},
    ]
    assert sources == [input_info1, input_info2]