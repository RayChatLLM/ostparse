"""Standalone driver: run plugin subcommands outside RayChat.

Each argument is one complete subcommand string; they share session state,
exactly as consecutive tool calls in a RayChat session do::

    python3 -m ostparse_raychat "open /tmp/small.ost" "search budget" "show 0x200024"

With no arguments it reads one subcommand per line from stdin.
"""

from __future__ import annotations

import sys

from .commands import run


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    state: dict[str, object] = {}
    commands = args or (line.strip() for line in sys.stdin)
    for command in commands:
        if not command:
            continue
        print(f"$ ostparse {command}")
        print(run(command, None, state))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
