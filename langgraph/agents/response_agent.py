from state import AgentState

def response_node(state: AgentState) -> AgentState:
    state["notes"].append("[response] stub — not yet implemented")
    return state
