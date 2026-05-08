"""Reverse-engineering agent builder."""

from __future__ import annotations


def build_re_agent(*, AgentCls, model: str, tool_list_functions, tool_reverse_engineering_leads, tool_decompile, agent_settings=None):
    settings = (agent_settings(750) if agent_settings else {})
    return AgentCls(
        name="ReverseEngineeringAgent",
        model=model,
        tools=[tool_list_functions, tool_reverse_engineering_leads, tool_decompile],
        instructions=(
            "Goal: RE triage with evidence. Do not guess.\n"
            "- First, use tool_reverse_engineering_leads to get priority functions, suspicious strings, and xrefs.\n"
            "- Then, correlate: show string -> xref -> function -> (optionally) decompile that function.\n"
            "- If asked 'where do I start?', output 3-6 concrete next steps naming functions and xrefs.\n"
            "Never present isolated strings without provenance if xrefs are available."
        ),
        **settings,
    )

