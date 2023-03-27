import pytest

from ddtrace.appsec import _asm_request_context


@pytest.fixture(autouse=True)
def reset_test_asm_context():
    _asm_request_context.reset()
    yield
    _asm_request_context.reset()


_TEST_IP = "1.2.3.4"
_TEST_HEADERS = {"foo": "bar"}


def test_context_set_and_reset():
    _asm_request_context.asm_request_context_set(_TEST_IP, _TEST_HEADERS, True, lambda: True)
    assert _asm_request_context.get_address("REQUEST_HTTP_IP") == _TEST_IP
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES") == _TEST_HEADERS
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
    assert _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get() is not None
    _asm_request_context.reset()
    assert _asm_request_context.get_address("REQUEST_HTTP_IP") is None
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES") is None
    assert _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get() is None
    assert not _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
    _asm_request_context.asm_request_context_set(_TEST_IP, _TEST_HEADERS)
    assert not _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
    assert not _asm_request_context.block_request()


def test_set_get_ip():
    _asm_request_context.set_address("REQUEST_HTTP_IP", _TEST_IP)
    assert _asm_request_context.get_address("REQUEST_HTTP_IP") == _TEST_IP


def test_set_get_headers():
    _asm_request_context.set_address("REQUEST_HEADERS_NO_COOKIES", _TEST_HEADERS)
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES") == _TEST_HEADERS


def test_call_block_callable_none():
    _asm_request_context.set_block_request_callable(None)
    assert not _asm_request_context.block_request()
    _asm_request_context.reset()
    assert not _asm_request_context.block_request()


def test_call_block_callable_noargs():
    def _callable():
        return 42

    _asm_request_context.set_block_request_callable(_callable)
    assert _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get()() == 42
    _asm_request_context.reset()
    assert not _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get()


def test_call_block_callable_curried():
    class TestException(Exception):
        pass

    def _callable():
        raise TestException()

    _asm_request_context.set_block_request_callable(_callable)
    with pytest.raises(TestException):
        assert _asm_request_context.block_request()


def test_set_get_headers_case_sensitive():
    # default reset value should be False
    assert not _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
    _asm_request_context.set_address("REQUEST_HEADERS_NO_COOKIES_CASE", True)
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
    _asm_request_context.set_address("REQUEST_HEADERS_NO_COOKIES_CASE", False)
    assert not _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")


def test_asm_request_context_manager():
    with _asm_request_context.asm_request_context_manager(_TEST_IP, _TEST_HEADERS, True, lambda: 42):
        assert _asm_request_context.get_address("REQUEST_HTTP_IP") == _TEST_IP
        assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES") == _TEST_HEADERS
        assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
        assert _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get()() == 42

    assert _asm_request_context.get_address("REQUEST_HTTP_IP") is None
    assert _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES") is None
    assert _asm_request_context._DD_BLOCK_REQUEST_CALLABLE.get() is None
    assert not _asm_request_context.get_address("REQUEST_HEADERS_NO_COOKIES_CASE")
