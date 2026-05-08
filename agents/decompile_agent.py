"""Decompile agent builder."""

from __future__ import annotations


def build_decompile_agent(*, AgentCls, model: str, tool_decompile, agent_settings=None):
    settings = (agent_settings(900) if agent_settings else {})
    return AgentCls(
        name="DecompileAgent",
        model=model,
        tools=[tool_decompile],
        instructions=(
            "Use tool_decompile for the named function. Summarize what it does and cite concrete evidence:\n"
            "- function name and any referenced strings\n"
            "- imports or APIs called inside the function\n"
            "- relevant branches (success/failure) when visible\n"
            "Then provide defensive guidance: what to fix and why. Never claim vulnerabilities without evidence."
        ),
        **settings,
    )

