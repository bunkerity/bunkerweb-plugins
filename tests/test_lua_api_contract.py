"""Every answering ``api()`` return must carry an explicit HTTP status.

``api.lua``'s ``do_api_call()`` hands a plugin's status straight to ``ngx.status``
(``confs/api.conf``). ``self:ret(true, msg)`` with no third argument leaves it nil, and
OpenResty raises ``bad argument #2 to 'ngx_http_lua_ffi_set_resp_status' (cannot convert
'nil' to 'int')``. The request then 500s with nginx's HTML error page instead of the JSON
envelope the caller parses, so the web UI's ``get_ping`` sees ``Expecting value: line 1
column 1 (char 0)`` rather than a status.

Only ``self:ret(true, ...)`` matters: a falsy ``ret`` means "not handled here" and
``do_api_call`` moves on to the next plugin without building a response.
"""

from pathlib import Path
from re import DOTALL, M, finditer, search

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _api_body(source):
    """The text of the plugin's ``api()`` method, or None when it has none."""
    match = search(r"^function \w+:api\(\).*?^end$", source, DOTALL | M)
    return match.group(0) if match else None


def _split_args(call):
    """Top-level comma split, so a comma inside a string or a nested call doesn't count."""
    args, depth, quote, current = [], 0, None, ""
    for char in call:
        if quote:
            current += char
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(current)
            current = ""
            continue
        current += char
    args.append(current)
    return args


def _statusless_returns(body):
    """Every ``self:ret(true, …)`` in the body that passes no third argument."""
    offenders = []
    for match in finditer(r"self:ret\(", body):
        start = match.end()
        depth, index = 1, start
        while index < len(body) and depth:
            if body[index] == "(":
                depth += 1
            elif body[index] == ")":
                depth -= 1
            index += 1
        # Bind the bound before slicing: black wants spaces around a colon whose operand
        # is an expression, and flake8 calls that E203.
        closing = index - 1
        call = body[start:closing]
        args = _split_args(call)
        if args and args[0].strip() == "true" and len(args) < 3:
            offenders.append(call.strip())
    return offenders


def _plugins():
    for manifest in sorted(ROOT.glob("*/plugin.json")):
        lua = manifest.parent / f"{manifest.parent.name}.lua"
        if lua.is_file():
            yield pytest.param(lua, id=manifest.parent.name)


@pytest.mark.parametrize("lua", list(_plugins()))
def test_every_answering_api_return_carries_a_status(lua):
    body = _api_body(lua.read_text())
    if body is None:
        pytest.skip("no api() handler")
    offenders = _statusless_returns(body)
    assert not offenders, (
        f"{lua.name}: api() answers without an HTTP status, which sets ngx.status = nil and "
        f"makes the endpoint 500 with an HTML body instead of JSON: {offenders}"
    )
