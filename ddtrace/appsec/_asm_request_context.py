import contextlib
from typing import TYPE_CHECKING

from ddtrace import config
from ddtrace.internal.logger import get_logger


if TYPE_CHECKING:
    from typing import Any
    from typing import Callable
    from typing import Generator
    from typing import Optional
    from typing import Tuple
    from typing import Union
    from typing import Iterable

from ddtrace.appsec._constants import SPAN_DATA_NAMES
from ddtrace.contrib import trace_utils
from ddtrace.internal import _context
from ddtrace.vendor import contextvars


log = get_logger(__name__)


def _transform_headers(data):
    # type: (Union[dict[str, str], list[Tuple[str, str]]]) -> dict[str, Union[str, list[str]]]
    normalized = {}  # type: dict[str, Union[str, list[str]]]
    headers = data if isinstance(data, list) else data.items()
    for header, value in headers:
        header = header.lower()
        if header in ("cookie", "set-cookie"):
            continue
        if header in normalized:  # if a header with the same lowercase name already exists, let's make it an array
            existing = normalized[header]
            if isinstance(existing, list):
                existing.append(value)
            else:
                normalized[header] = [existing, value]
        else:
            normalized[header] = value
    return normalized


"""
Stopgap module for providing ASM context for the blocking features wrapping some
contextvars. When using this, note that context vars are always thread-local so each
thread will have a different context.
"""


# FIXME: remove these and use the new context API once implemented and allowing
# contexts without spans

_DD_RESPONSE_CONTENT_TYPE = contextvars.ContextVar("datadog_response_content_type", default="text/json")
_DD_BLOCK_REQUEST_CALLABLE = contextvars.ContextVar("datadog_block_request_callable_contextvar", default=None)
_DD_WAF_CALLBACK = contextvars.ContextVar("datadog_early_waf_callback", default=None)
_DD_WAF_DATA = contextvars.ContextVar("datadog_waf_data", default=None)

_DD_WAF_RESULTS = contextvars.ContextVar("datadog_early_waf_results", default=([[], [], []]))


def reset():  # type: () -> None
    _DD_RESPONSE_CONTENT_TYPE.set("text/json")
    _DD_BLOCK_REQUEST_CALLABLE.set(None)
    set_waf_callback(None, None, {})


# Note: get/set headers use Any since we just carry the headers here without changing or using them
# and different frameworks use different types that we don't want to force it into a Mapping at the
# early point set_headers is usually called


def set_block_request_callable(_callable):  # type: (Optional[Callable]) -> None
    """
    Sets a callable that could be use to do a best-effort to block the request. If
    the callable need any params, like headers, they should be curried with
    functools.partial.
    """
    if _callable:
        _DD_BLOCK_REQUEST_CALLABLE.set(_callable)


def block_request():  # type: () -> None
    """
    Calls or returns the stored block request callable, if set.
    """
    _callable = _DD_BLOCK_REQUEST_CALLABLE.get()
    if _callable:
        _callable()

    log.debug("Block request called but block callable not set by framework")


def get_response_content_type():
    return _DD_RESPONSE_CONTENT_TYPE.get()


def set_waf_callback(callback, span, required_adresses):  # type: (Any, Any, Iterable[str]|None) -> None
    _DD_WAF_CALLBACK.set((callback, span))
    current_directory = _DD_WAF_DATA.get()
    if current_directory is None:
        current_directory = {}
    if required_adresses is not None:
        _DD_WAF_DATA.set({key: current_directory.get(key, None) for key in required_adresses})


def is_address_needed(name):  # type: (str) -> bool
    address_dict = _DD_WAF_DATA.get()
    return name in address_dict and address_dict[name] is None


def is_address_available(name):  # type: (str) -> bool
    address_dict = _DD_WAF_DATA.get()
    return name in address_dict and address_dict[name] is not None


def set_address(name, value):  # type: (str, Any) -> None
    """Should only be called if need_adress returns true outside of tests"""
    main_data = _DD_WAF_DATA.get()
    if name.endswith("HEADERS_NO_COOKIES") and value is not None:
        value = _transform_headers(value)
    if name == "REQUEST_HEADERS_NO_COOKIES":
        if "text/html" in value.get("Accept", ""):
            _DD_RESPONSE_CONTENT_TYPE.set("text/html")
    main_data[name] = value


def get_address(name):  # type: (str) -> Any
    main_data = _DD_WAF_DATA.get()
    return main_data.get(name)


def call_waf_callback(custom_data=None):
    # type: (dict[str, Any] | None) -> None
    if not config._appsec_enabled:
        return
    callback, span = _DD_WAF_CALLBACK.get()
    if callback:
        main_data = _DD_WAF_DATA.get()
        for k, v in main_data.items():
            if v is None:
                res = _context.get_item(SPAN_DATA_NAMES[k], span=span)
                if res is not None:
                    set_address(k, res)
        if custom_data:
            data = custom_data
            for k, v in list(data.items()):
                if v is None:
                    value = main_data.get(k, None)
                    if value is None:
                        del data[k]
                    else:
                        data[k] = value
        else:
            data = {k: v for k, v in main_data.items() if v is not None}
        if data:
            for k in data:
                main_data.pop(k, None)
            return callback(data)
    else:
        log.warning("WAF callback called but not set")


def asm_request_context_set(remote_ip=None, headers=None, headers_case_sensitive=False, block_request_callable=None):
    # type: (Optional[str], Any, bool, Optional[Callable]) -> None
    _DD_WAF_DATA.set({})
    set_waf_callback(None, None, None)
    set_address("REQUEST_HEADERS_NO_COOKIES", headers)
    set_address("REQUEST_HEADERS_NO_COOKIES_CASE", headers_case_sensitive)
    if headers is not None and remote_ip is not None:
        remote_ip = trace_utils._get_request_header_client_ip(headers, remote_ip, headers_case_sensitive)

    set_address("REQUEST_HTTP_IP", remote_ip)
    set_block_request_callable(block_request_callable)


def set_waf_results(result_data, result_info, is_blocked):  # type: (Any, Any, bool) -> None
    list_results_data, list_result_info, list_is_blocked = get_waf_results()
    list_results_data.append(result_data)
    list_result_info.append(result_info)
    list_is_blocked.append(is_blocked)
    _DD_WAF_RESULTS.set((list_results_data, list_result_info, list_is_blocked))


def get_waf_results():  # type: () -> Tuple[list[Any], list[Any], list[bool]]
    return _DD_WAF_RESULTS.get()


def reset_waf_results():  # type: () -> None
    _DD_WAF_RESULTS.set([[], [], []])


@contextlib.contextmanager
def asm_request_context_manager(
    remote_ip=None, headers=None, headers_case_sensitive=False, block_request_callable=None
):
    # type: (Optional[str], Any, bool, Optional[Callable]) -> Generator[None, None, None]
    asm_request_context_set(remote_ip, headers, headers_case_sensitive, block_request_callable)
    try:
        yield
    finally:
        reset()
