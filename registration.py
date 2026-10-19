"""Bind the /ostparse command family and model tool to the vendored OST reader."""

from __future__ import annotations

from typing import TYPE_CHECKING

from raychat.sdk import CommandDefinition, ToolDefinition

from .commands import DEFAULTS, SUBCOMMANDS, run

if TYPE_CHECKING:
    from collections.abc import Mapping

    from raychat.sdk import PluginContext, PluginRegistrar

_STATE_KEY = "store"


def register(api: PluginRegistrar) -> None:
    """Register the /ostparse operator command and the model tool action."""

    def validate_settings(settings: Mapping[str, object]) -> None:
        for key in DEFAULTS:
            value = settings.get(key, DEFAULTS[key])
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                message = f"ostparse.{key} must be a non-negative integer"
                raise ValueError(message)

    api.validate_settings(validate_settings)

    def _run(arguments: str, ctx: PluginContext) -> str:
        state = ctx.state.setdefault(_STATE_KEY, {})
        if not isinstance(state, dict):
            state = {}
            ctx.state[_STATE_KEY] = state
        return run(arguments, ctx.settings, state, ctx.check_cancelled, ctx.workspace)

    def command(arguments: str, ctx: PluginContext) -> str:
        result = _run(arguments or "", ctx)
        ctx.checkpoint()
        return result

    api.register_command(
        CommandDefinition(
            "ostparse",
            command,
            description=(
                "Search/analyze an OST/PST mail file: open, info, tree, index,"
                " search, count, show, export, stats"
            ),
            usage="/ostparse SUBCOMMAND [args]",
        ),
    )

    def validate_action(action: dict[str, object]) -> None:
        command_text = action.get("command")
        if not isinstance(command_text, str) or not command_text.strip():
            message = (
                'ostparse requires a non-empty string "command", e.g.'
                ' "search from:alice received:last month"'
            )
            raise ValueError(message)
        sub = command_text.split()[0].lower()
        if sub not in SUBCOMMANDS:
            listed = ", ".join(SUBCOMMANDS)
            message = f"unknown ostparse subcommand {sub!r}; expected one of {listed}"
            raise ValueError(message)
        extra = set(action) - {"action", "command"}
        if extra:
            message = "unexpected ostparse fields: " + ", ".join(sorted(extra))
            raise ValueError(message)

    def execute_tool(
        action: dict[str, object],
        ctx: PluginContext,
    ) -> Mapping[str, object]:
        return {"ok": True, "output": _run(str(action["command"]).strip(), ctx)}

    api.register_tool(
        ToolDefinition(
            "ostparse",
            "Search and analyze email in an Outlook OST/PST file on disk:"
            " open FILE, then search with Outlook/AQS query syntax"
            " (from:/to:/subject:/hasattachment:/received:last week/"
            '"phrases"/wildcards//regex//), show one message, count,'
            " facet, or export hits as .eml — same subcommands as /ostparse",
            validate_action,
            execute_tool,
            requires_approval=False,
            parameters={"required": ["command"], "optional": []},
        ),
    )
