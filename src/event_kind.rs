//! Shared classifications for open-ended journal event kind strings.

use crate::compaction::{
    COMPACTION_ABORTED_KIND, COMPACTION_CHECKPOINT_KIND, COMPACTION_FAILED_KIND,
    COMPACTION_STARTED_KIND,
};

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

/// Whether a compaction attempt has reached a terminal state.
pub(crate) fn is_compaction_terminal(kind: &str) -> bool {
    matches!(
        kind,
        COMPACTION_CHECKPOINT_KIND | COMPACTION_FAILED_KIND | COMPACTION_ABORTED_KIND
    )
}

/// Whether an event participates in a compaction attempt's lifecycle.
pub(crate) fn is_compaction_lifecycle(kind: &str) -> bool {
    kind == COMPACTION_STARTED_KIND || is_compaction_terminal(kind)
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
        }

        for kind in ["response.completed", "response.failed", "response.aborted"] {
            assert!(is_response_terminal(kind), "{kind}");
        }

        for kind in ["tool.started", "tool.in_doubt"] {
            assert!(!is_tool_terminal(kind), "{kind}");
            assert!(is_tool_lifecycle(kind), "{kind}");
        }
        assert!(!is_response_terminal("response.started"));

        for kind in [
            COMPACTION_CHECKPOINT_KIND,
            COMPACTION_FAILED_KIND,
            COMPACTION_ABORTED_KIND,
        ] {
            assert!(is_compaction_terminal(kind), "{kind}");
            assert!(is_compaction_lifecycle(kind), "{kind}");
        }
        assert!(!is_compaction_terminal(COMPACTION_STARTED_KIND));
        assert!(is_compaction_lifecycle(COMPACTION_STARTED_KIND));

        for kind in [
            "context.instructions",
            "render.compact",
            "vendor.future_event",
        ] {
            assert!(!is_tool_lifecycle(kind), "{kind}");
            assert!(!is_compaction_lifecycle(kind), "{kind}");
        }
    }
}
