"""
FortifyAI LangGraph Pipeline
-----------------------------
All pipeline nodes are registered here. In Iteration 1 every node is a
stub that logs its name and passes state through unchanged.
Real logic is wired in subsequent iterations.

Node execution order (happy path):
  triage → version_resolver → context → api_diff
         → ai_reasoning → adr_fix → pr_agent → fortify_writeback → END

Conditional edges (retry / escalate) are declared as stubs now and will
be filled in during Iterations 8 & 9.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph
from loguru import logger

from agents.triage import triage_node
from agents.version_resolver import version_resolver_node
from state import AgentState


# ── Stub node helpers ─────────────────────────────────────────────────────────

def _stub(name: str, state: AgentState) -> AgentState:
    """Generic stub: log the node name and return state unchanged."""
    logger.info(f"[{name}] node reached (stub — not yet implemented)")
    state["audit_trail"].append({"node": name, "status": "stub"})
    return state


# ── Node definitions (stubs) ──────────────────────────────────────────────────

def triage(state: AgentState) -> AgentState:
    """
    Iteration 3: Filter findings — skip suppressed / non-OSS / non-fixable.
    Delegates to agents.triage.triage_node.
    """
    return triage_node(state)


def version_resolver(state: AgentState) -> AgentState:
    """
    Iteration 4: Resolve next/greatest safe version from Fortify recommendations.
    Client is injected via closure when the graph is invoked — see fortifyai.py.
    Stub until client is bound; delegates to agents.version_resolver.version_resolver_node.
    """
    client = state.get("_client")  # type: ignore[attr-defined]
    if client is None:
        return _stub("VersionResolver", state)
    return version_resolver_node(state, client)


def context_agent(state: AgentState) -> AgentState:
    """
    Iteration 5: Locate dep in codebase — pom files + calling Java files.
    """
    return _stub("Context", state)


def api_diff_agent(state: AgentState) -> AgentState:
    """
    Iteration 6: Run japicmp, parse breaking changes, map to calling files.
    """
    return _stub("ApiDiff", state)


def ai_reasoning_agent(state: AgentState) -> AgentState:
    """
    Iteration 7: ChatVertexAI safety judgment — high/medium/low confidence.
    """
    return _stub("AiReasoning", state)


def adr_fix_agent(state: AgentState) -> AgentState:
    """
    Iteration 8: Invoke adr.py --commit --push, parse exit code + branch.
    """
    return _stub("AdrFix", state)


def failure_analysis_agent(state: AgentState) -> AgentState:
    """
    Iteration 9: Parse Maven error log, prepare context for AI code fix.
    """
    return _stub("FailureAnalysis", state)


def ai_code_fix_agent(state: AgentState) -> AgentState:
    """
    Iteration 9: AI-generated patch for broken call sites after upgrade.
    """
    return _stub("AiCodeFix", state)


def pr_agent(state: AgentState) -> AgentState:
    """
    Iteration 10: Create GitHub PR with full context, labels, draft flag.
    """
    return _stub("PrAgent", state)


def fortify_writeback_agent(state: AgentState) -> AgentState:
    """
    Iteration 11: Post fix outcome comment back to each Fortify vulnerability.
    """
    return _stub("FortifyWriteback", state)


def escalate(state: AgentState) -> AgentState:
    """Terminal node: log escalation reason and mark state."""
    logger.warning(
        f"[Escalate] Escalating — reason: {state.get('escalation_reason', 'unknown')}"
    )
    state["status"] = "escalated"
    state["audit_trail"].append(
        {"node": "Escalate", "reason": state.get("escalation_reason")}
    )
    return state


# ── Routing functions (stubs) ─────────────────────────────────────────────────

def route_triage(
    state: AgentState,
) -> Literal["version_resolver", "escalate", END]:  # type: ignore[valid-type]
    """
    Iteration 3 will implement real skip logic.
    Stub: always proceed.
    """
    if state["status"] == "skipped":
        return END
    if state["status"] == "escalated":
        return "escalate"
    return "version_resolver"


def route_ai_reasoning(
    state: AgentState,
) -> Literal["adr_fix", "ai_code_fix", "escalate"]:
    """
    Iteration 7 will implement confidence-based routing.
    Stub: always go to adr_fix.
    """
    return "adr_fix"


def route_build_result(
    state: AgentState,
) -> Literal["pr_agent", "failure_analysis", "escalate"]:
    """
    Iteration 8 will implement exit-code routing.
    Stub: always pass.
    """
    return "pr_agent"


def route_retry(
    state: AgentState,
) -> Literal["adr_fix", "version_resolver", "escalate"]:
    """
    Iteration 9 will implement retry counter + next-candidate logic.
    Stub: always escalate.
    """
    return "escalate"


# ── Graph assembly ────────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    """
    Assemble and compile the full FortifyAI LangGraph pipeline.
    Returns a compiled graph ready to invoke.
    """
    graph = StateGraph(AgentState)

    # Register all nodes
    graph.add_node("triage", triage)
    graph.add_node("version_resolver", version_resolver)
    graph.add_node("context", context_agent)
    graph.add_node("api_diff", api_diff_agent)
    graph.add_node("ai_reasoning", ai_reasoning_agent)
    graph.add_node("adr_fix", adr_fix_agent)
    graph.add_node("failure_analysis", failure_analysis_agent)
    graph.add_node("ai_code_fix", ai_code_fix_agent)
    graph.add_node("pr_agent", pr_agent)
    graph.add_node("fortify_writeback", fortify_writeback_agent)
    graph.add_node("escalate", escalate)

    # Entry point
    graph.set_entry_point("triage")

    # ── Edges ─────────────────────────────────────────────────────────────────

    # Triage → branch
    graph.add_conditional_edges(
        "triage",
        route_triage,
        {
            "version_resolver": "version_resolver",
            "escalate": "escalate",
            END: END,
        },
    )

    # Happy path (no conditionals yet)
    graph.add_edge("version_resolver", "context")
    graph.add_edge("context", "api_diff")
    graph.add_edge("api_diff", "ai_reasoning")

    # AI reasoning → branch on confidence
    graph.add_conditional_edges(
        "ai_reasoning",
        route_ai_reasoning,
        {
            "adr_fix": "adr_fix",
            "ai_code_fix": "ai_code_fix",
            "escalate": "escalate",
        },
    )

    # Pre-patch AI code fix → ADR fix
    graph.add_edge("ai_code_fix", "adr_fix")

    # ADR fix → branch on build result
    graph.add_conditional_edges(
        "adr_fix",
        route_build_result,
        {
            "pr_agent": "pr_agent",
            "failure_analysis": "failure_analysis",
            "escalate": "escalate",
        },
    )

    # Retry loop
    graph.add_conditional_edges(
        "failure_analysis",
        route_retry,
        {
            "adr_fix": "adr_fix",
            "version_resolver": "version_resolver",  # try next candidate
            "escalate": "escalate",
        },
    )

    # PR → writeback → end
    graph.add_edge("pr_agent", "fortify_writeback")
    graph.add_edge("fortify_writeback", END)

    # Escalate → end
    graph.add_edge("escalate", END)

    logger.info("[Graph] Pipeline graph assembled — all nodes registered")
    return graph


# ── Convenience: pre-compiled singleton ──────────────────────────────────────

_compiled_graph = None


def get_compiled_graph():
    """Return a cached compiled graph (compiled once on first call)."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph().compile()
        logger.info("[Graph] Graph compiled successfully")
    return _compiled_graph
