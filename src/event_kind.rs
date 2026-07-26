//! Shared classifications for open-ended journal event kind strings.

/// Whether a tool event settles a call and supplies its final outcome.
pub(crate) fn is_tool_terminal(kind: &str) -> bool {
    matches!(
        kind,
        "tool.completed"
            | "tool.cancelled"
            | "tool.in_doubt_resolved"
            | "tool.skipped_due_to_cancel"
            | "tool.skipped_due_to_in_doubt"
            | "tool.skipped_due_to_limit"
            | "tool.skipped_due_to_stalled"
            | "tool.skipped_due_to_recovery"
    )
}

/// Whether an event participates in a tool call's lifecycle.
pub(crate) fn is_tool_lifecycle(kind: &str) -> bool {
    matches!(kind, "tool.started" | "tool.in_doubt") || is_tool_terminal(kind)
}

/// Whether a response attempt has reached a terminal state.
pub(crate) fn is_response_terminal(kind: &str) -> bool {
    matches!(
        kind,
        "response.completed" | "response.failed" | "response.aborted"
    )
}

/// Whether an event participates in a response attempt's lifecycle.
pub(crate) fn is_response_lifecycle(kind: &str) -> bool {
    kind == "response.started" || is_response_terminal(kind)
}

/// Whether a known event kind must belong to exactly one user turn.
pub(crate) fn is_turn_scoped(kind: &str) -> bool {
    matches!(
        kind,
        "user.message"
            | "turn.completed"
            | "turn.cancelled"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
    ) || is_response_lifecycle(kind)
        || is_tool_lifecycle(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_compose_without_closing_the_event_namespace() {
        for kind in [
            "tool.completed",
            "tool.cancelled",
            "tool.in_doubt_resolved",
            "tool.skipped_due_to_cancel",
            "tool.skipped_due_to_in_doubt",
            "tool.skipped_due_to_limit",
            "tool.skipped_due_to_stalled",
            "tool.skipped_due_to_recovery",
        ] {
            assert!(is_tool_terminal(kind), "{kind}");
            assert!(is_tool_lifecycle(kind), "{kind}");
            assert!(is_turn_scoped(kind), "{kind}");
        }

        for kind in ["response.completed", "response.failed", "response.aborted"] {
            assert!(is_response_terminal(kind), "{kind}");
            assert!(is_response_lifecycle(kind), "{kind}");
            assert!(is_turn_scoped(kind), "{kind}");
        }

        for kind in ["tool.started", "tool.in_doubt"] {
            assert!(!is_tool_terminal(kind), "{kind}");
            assert!(is_tool_lifecycle(kind), "{kind}");
            assert!(is_turn_scoped(kind), "{kind}");
        }
        assert!(!is_response_terminal("response.started"));
        assert!(is_response_lifecycle("response.started"));
        assert!(is_turn_scoped("response.started"));

        for kind in [
            "user.message",
            "turn.completed",
            "turn.cancelled",
            "agent.stalled",
            "agent.limit_reached",
            "context.limit_reached",
        ] {
            assert!(is_turn_scoped(kind), "{kind}");
        }

        for kind in [
            "context.instructions",
            "render.compact",
            "compaction.started",
            "vendor.future_event",
        ] {
            assert!(!is_tool_lifecycle(kind), "{kind}");
            assert!(!is_response_lifecycle(kind), "{kind}");
            assert!(!is_turn_scoped(kind), "{kind}");
        }
    }
}
