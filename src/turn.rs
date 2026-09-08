//! Deterministic turn boundaries derived from canonical journal events.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::compaction::validate_provider_budget_retries_v1;
use crate::error::{OxidraError, Result};
use crate::mcp::{
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1, MCP_CALL_CHAIN_VALIDATOR_VERSION_V2,
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V4, validate_mcp_call_chain_for_version,
    validate_mcp_call_chain_through_version,
};
use crate::session::JournalEvent;

pub const TURN_BOUNDARY_VALIDATOR_VERSION: u32 = 8;
pub const TURN_BOUNDARY_VERSION: u64 = TURN_BOUNDARY_VALIDATOR_VERSION as u64;
const TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6: u32 = MCP_CALL_CHAIN_VALIDATOR_VERSION_V1;
const TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V7: u32 = MCP_CALL_CHAIN_VALIDATOR_VERSION_V2;
const TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V8: u32 = MCP_CALL_CHAIN_VALIDATOR_VERSION_V4;
const PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V3: u32 =
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V1;
const PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V4: u32 =
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V2;
const PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V5: u32 =
    MCP_CALL_CHAIN_VALIDATOR_VERSION_V4;
/// Default slot reducer for a new writer. Persisted compaction boundary
/// policies bind their own historical version and must not read this constant.
#[allow(dead_code)]
pub(crate) const PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION: u32 = 5;

/// Frozen turn reducers historically treated these root fields as protocol
/// markers independently of `kind`.  Keep that literal reader behavior for
/// legacy schema-1 journals; the public custom-event writer prevents new
/// extension payloads from placing caller-controlled fields at this root.
fn has_inline_turn_completion(event: &JournalEvent) -> bool {
    event.data.get("turn_completion").is_some()
}

fn direct_turn_boundary_version_mut(event: &mut JournalEvent) -> Option<&mut Value> {
    event.data.get_mut("turn_boundary_version")
}

fn inline_turn_boundary_version_mut(event: &mut JournalEvent) -> Option<&mut Value> {
    event
        .data
        .get_mut("turn_completion")
        .and_then(Value::as_object_mut)
        .and_then(|completion| completion.get_mut("turn_boundary_version"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionEvidence {
    ExplicitMarker,
    InlineResponse,
    LegacyNextUser,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnState {
    Complete(CompletionEvidence),
    Cancelled,
    Aborted,
    Failed,
    Stalled,
    LimitReached,
    InDoubt,
    Incomplete,
    OpenTail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnSpan {
    pub turn_id: String,
    pub start_index: usize,
    pub end_index_exclusive: usize,
    pub covers_from_seq: u64,
    pub covers_through_seq: u64,
    pub state: TurnState,
    /// The earliest event sequence accepted as completion evidence.  This is
    /// separate from `covers_through_seq`: a legacy cutoff may include later
    /// projection-neutral events, and an explicit marker may follow an already
    /// validated inline completion.
    pub completion_seq: Option<u64>,
    /// Whether a later complete boundary may safely cover this turn.
    pub cut_safe: bool,
}

/// Versioned Provider request-slot reducer output.  This is intentionally not
/// folded into `TurnState`: turn completion and permission to dispatch the
/// next Provider request are different state machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRequestSlotState {
    Ready,
    ResponseInFlight,
    AwaitingTools,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletePrefix {
    /// Number of successfully completed turns covered by this cutoff.
    pub turn_count: usize,
    pub covers_through_seq: u64,
}

/// 已通过验证的显式放弃事件；调用方只能使用该 reducer 的结果改变 projection。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAbandon {
    pub turn_id: String,
    pub user_message_seq: u64,
    pub limit_seq: u64,
    pub abandon_seq: u64,
}

/// 已通过验证的持久化 retry 意图。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedRetry {
    pub retry_id: String,
    pub turn_id: String,
    pub user_message_seq: u64,
    pub limit_seq: u64,
    pub retry_seq: u64,
}

/// turn recovery 控制事件的唯一共享 reducer 输出。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ValidatedTurnRecovery {
    pub abandons: HashMap<String, ValidatedAbandon>,
    pub retries: Vec<ValidatedRetry>,
}

/// 校验并归约 turn recovery 控制事件，防止任意 journal 行获得历史删除或
/// 重试状态迁移语义。
///
/// 放弃只适用于尚未完成、确实经历过 context-limit 的 turn；引用、顺序和
/// 重复事件任一不成立时都 fail closed。
#[cfg(test)]
pub(crate) fn validate_turn_recovery(events: &[JournalEvent]) -> Result<ValidatedTurnRecovery> {
    validate_turn_recovery_v3(events)
}

/// Validate a complete journal using the recovery language selected by each
/// owning `user.message`.
///
/// This is the runtime/full-history entry point. Frozen reducers continue to
/// call their literal v2 or v3 validator directly so persisted artifacts keep
/// their published semantics.
pub(crate) fn validate_turn_recovery_dynamic(
    events: &[JournalEvent],
) -> Result<ValidatedTurnRecovery> {
    let turn_versions = resolve_user_turn_boundary_versions(events)?;
    validate_turn_recovery_for_versions(events, &turn_versions)
}

/// Validate recovery controls in the language of the turn that owns them.
///
/// `segment_turns` may need a newer reducer for a later turn, but that must not
/// make an older turn adopt the newer recovery ordering rules.  In particular,
/// v2 allowed a durable `context.limit_reached` to precede its `user.message`,
/// while v3 requires the opposite ordering and binds provider limits to a
/// failed response attempt.  Running one global v3 validator over a mixed
/// journal therefore rejects legal historical prefixes as soon as a later
/// v8 turn appears.
///
/// The per-turn validators intentionally receive only events belonging to that
/// turn; recovery state is turn-scoped.  Retry identifiers remain globally
/// unique, matching the frozen whole-journal validators.
fn validate_turn_recovery_for_versions(
    events: &[JournalEvent],
    turn_versions: &HashMap<String, u32>,
) -> Result<ValidatedTurnRecovery> {
    let mut recovery = ValidatedTurnRecovery::default();
    let mut seen_retry_ids = HashSet::new();
    let mut event_indices_by_turn = HashMap::<&str, Vec<usize>>::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(turn_id) = event.turn_id.as_deref() {
            event_indices_by_turn
                .entry(turn_id)
                .or_default()
                .push(index);
        }
    }

    // A partitioned validator must not silently drop protocol rows that have
    // no owning user turn. These are exactly the event classes consumed by
    // recovery v2/v3, plus the historical root-level inline marker.
    for event in events.iter().filter(|event| {
        is_turn_recovery_owned_event_kind(&event.kind) || has_inline_turn_completion(event)
    }) {
        let inline = has_inline_turn_completion(event);
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            let label = if inline {
                "inline turn completion"
            } else {
                event.kind.as_str()
            };
            OxidraError::Session(format!("{label} at seq {} has no turn_id", event.seq))
        })?;
        if !turn_versions.contains_key(turn_id) {
            let label = if inline {
                "inline turn completion"
            } else {
                event.kind.as_str()
            };
            return Err(OxidraError::Session(format!(
                "{label} at seq {} references unknown turn {turn_id}",
                event.seq
            )));
        }
    }

    let mut validated_turns = HashSet::new();
    for event in events.iter().filter(|event| event.kind == "user.message") {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        if !validated_turns.insert(turn_id) {
            continue;
        }
        let version = turn_versions.get(turn_id).copied().unwrap_or(1);
        let scoped = event_indices_by_turn
            .get(turn_id)
            .into_iter()
            .flatten()
            .map(|index| events[*index].clone())
            .collect::<Vec<_>>();
        let scoped_recovery = if version >= 3 {
            validate_turn_recovery_v3(&scoped)?
        } else {
            validate_turn_recovery_v2(&scoped)?
        };

        for (retry_id, abandon) in scoped_recovery.abandons {
            if recovery
                .abandons
                .insert(retry_id.clone(), abandon)
                .is_some()
            {
                return Err(OxidraError::Session(format!(
                    "turn {retry_id} has duplicate recovery ownership"
                )));
            }
        }
        for retry in scoped_recovery.retries {
            if !seen_retry_ids.insert(retry.retry_id.clone()) {
                return Err(OxidraError::Session(format!(
                    "duplicate turn retry id {}",
                    retry.retry_id
                )));
            }
            recovery.retries.push(retry);
        }
    }

    Ok(recovery)
}

fn is_turn_recovery_owned_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "user.message"
            | "response.completed"
            | "response.failed"
            | "response.aborted"
            | "turn.completed"
            | "turn.cancelled"
            | "turn.abandoned"
            | "turn.retry_started"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
    )
}

fn legacy_pre_user_recovery_turns(
    events: &[JournalEvent],
    turn_versions: &HashMap<String, u32>,
) -> HashSet<String> {
    let users = events
        .iter()
        .filter(|event| event.kind == "user.message")
        .filter_map(|event| {
            let turn_id = event.turn_id.as_ref()?.clone();
            let version = turn_versions.get(&turn_id).copied().unwrap_or(1);
            (version <= 2).then_some((turn_id, event.seq))
        })
        .collect::<HashMap<_, _>>();
    events
        .iter()
        .filter(|event| event.kind == "context.limit_reached")
        .filter_map(|event| {
            let turn_id = event.turn_id.as_ref()?;
            let user_seq = users.get(turn_id)?;
            (event.seq < *user_seq).then_some(turn_id.clone())
        })
        .collect()
}

// v2 按 40e7930 的字面实现冻结；更严格的语义只能新增版本。
pub(crate) fn validate_turn_recovery_v2(events: &[JournalEvent]) -> Result<ValidatedTurnRecovery> {
    let mut users = HashMap::new();
    let mut limits: HashMap<String, Vec<u64>> = HashMap::new();
    let mut completion_seqs: HashMap<String, Vec<u64>> = HashMap::new();
    let mut response_terminal_seqs: HashMap<String, Vec<u64>> = HashMap::new();

    for event in events {
        match event.kind.as_str() {
            "user.message" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "user.message at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                if users.insert(turn_id.to_owned(), event.seq).is_some() {
                    return Err(OxidraError::Session(format!(
                        "turn {turn_id} has more than one user.message"
                    )));
                }
            }
            "context.limit_reached" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "context.limit_reached at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                limits
                    .entry(turn_id.to_owned())
                    .or_default()
                    .push(event.seq);
            }
            "turn.completed" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "turn.completed at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                completion_seqs
                    .entry(turn_id.to_owned())
                    .or_default()
                    .push(event.seq);
            }
            _ => {}
        }
        if matches!(
            event.kind.as_str(),
            "response.completed" | "response.failed" | "response.aborted"
        ) {
            let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                OxidraError::Session(format!(
                    "{} at seq {} has no turn_id",
                    event.kind, event.seq
                ))
            })?;
            response_terminal_seqs
                .entry(turn_id.to_owned())
                .or_default()
                .push(event.seq);
        }
        if has_inline_turn_completion(event) {
            let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                OxidraError::Session(format!(
                    "inline turn completion at seq {} has no turn_id",
                    event.seq
                ))
            })?;
            completion_seqs
                .entry(turn_id.to_owned())
                .or_default()
                .push(event.seq);
        }
    }

    let mut abandons = HashMap::new();
    for event in events.iter().filter(|event| event.kind == "turn.abandoned") {
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.abandoned at seq {} has no turn_id",
                event.seq
            ))
        })?;
        if abandons.contains_key(turn_id) {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has duplicate turn.abandoned events"
            )));
        }
        let user_message_seq = event
            .data
            .get("user_message_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.abandoned at seq {} has no user_message_seq",
                    event.seq
                ))
            })?;
        if users.get(turn_id) != Some(&user_message_seq) {
            return Err(OxidraError::Session(format!(
                "turn.abandoned at seq {} does not reference turn {turn_id}'s user.message",
                event.seq
            )));
        }
        if completion_seqs.contains_key(turn_id) {
            return Err(OxidraError::Session(format!(
                "completed turn {turn_id} cannot be abandoned"
            )));
        }
        let limit_seq = limits
            .get(turn_id)
            .and_then(|seqs| seqs.iter().copied().filter(|seq| *seq < event.seq).max())
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.abandoned at seq {} is not preceded by context.limit_reached",
                    event.seq
                ))
            })?;
        if event.seq <= user_message_seq {
            return Err(OxidraError::Session(format!(
                "turn.abandoned at seq {} precedes its user.message",
                event.seq
            )));
        }
        abandons.insert(
            turn_id.to_owned(),
            ValidatedAbandon {
                turn_id: turn_id.to_owned(),
                user_message_seq,
                limit_seq,
                abandon_seq: event.seq,
            },
        );
    }

    let mut retries = Vec::new();
    let mut retry_ids = HashSet::new();
    let mut previous_retry_seq: HashMap<String, u64> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "turn.retry_started")
    {
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.retry_started at seq {} has no turn_id",
                event.seq
            ))
        })?;
        let version = event
            .data
            .get("retry_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no retry_version",
                    event.seq
                ))
            })?;
        if version != 1 {
            return Err(OxidraError::Session(format!(
                "unsupported turn retry version {version} at seq {}",
                event.seq
            )));
        }
        let retry_id = event
            .data
            .get("retry_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no retry_id",
                    event.seq
                ))
            })?;
        if !retry_ids.insert(retry_id.to_owned()) {
            return Err(OxidraError::Session(format!(
                "duplicate turn retry id {retry_id}"
            )));
        }
        let user_message_seq = event
            .data
            .get("user_message_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no user_message_seq",
                    event.seq
                ))
            })?;
        if users.get(turn_id) != Some(&user_message_seq) {
            return Err(OxidraError::Session(format!(
                "turn.retry_started at seq {} does not reference turn {turn_id}'s user.message",
                event.seq
            )));
        }
        if completion_seqs
            .get(turn_id)
            .is_some_and(|seqs| seqs.iter().any(|seq| *seq < event.seq))
        {
            return Err(OxidraError::Session(format!(
                "completed turn {turn_id} cannot be retried"
            )));
        }
        if abandons
            .get(turn_id)
            .is_some_and(|abandon| abandon.abandon_seq < event.seq)
        {
            return Err(OxidraError::Session(format!(
                "abandoned turn {turn_id} cannot be retried"
            )));
        }
        let limit_seq = event
            .data
            .get("context_limit_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no context_limit_seq",
                    event.seq
                ))
            })?;
        let latest_limit = limits
            .get(turn_id)
            .and_then(|seqs| seqs.iter().copied().filter(|seq| *seq < event.seq).max())
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} is not preceded by context.limit_reached",
                    event.seq
                ))
            })?;
        if limit_seq != latest_limit {
            return Err(OxidraError::Session(format!(
                "turn.retry_started at seq {} does not reference the latest context limit",
                event.seq
            )));
        }
        if let Some(previous) = previous_retry_seq.get(turn_id) {
            let previous_was_settled = response_terminal_seqs
                .get(turn_id)
                .is_some_and(|seqs| seqs.iter().any(|seq| *seq > *previous && *seq < event.seq));
            if limit_seq <= *previous && !previous_was_settled {
                return Err(OxidraError::Session(format!(
                    "turn.retry_started at seq {} duplicates an undispatched retry intent",
                    event.seq
                )));
            }
        }
        previous_retry_seq.insert(turn_id.to_owned(), event.seq);
        retries.push(ValidatedRetry {
            retry_id: retry_id.to_owned(),
            turn_id: turn_id.to_owned(),
            user_message_seq,
            limit_seq,
            retry_seq: event.seq,
        });
    }

    Ok(ValidatedTurnRecovery { abandons, retries })
}

pub(crate) fn validate_turn_recovery_v3(events: &[JournalEvent]) -> Result<ValidatedTurnRecovery> {
    let mut users = HashMap::new();
    let mut limits: HashMap<String, Vec<&JournalEvent>> = HashMap::new();
    let mut failed_responses: HashMap<String, Vec<&JournalEvent>> = HashMap::new();
    let mut completion_seqs: HashMap<String, Vec<u64>> = HashMap::new();
    let mut attempt_terminal_seqs: HashMap<String, Vec<u64>> = HashMap::new();

    for event in events {
        match event.kind.as_str() {
            "user.message" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "user.message at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                if users.insert(turn_id.to_owned(), event.seq).is_some() {
                    return Err(OxidraError::Session(format!(
                        "turn {turn_id} has more than one user.message"
                    )));
                }
            }
            "context.limit_reached" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "context.limit_reached at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                limits.entry(turn_id.to_owned()).or_default().push(event);
            }
            "turn.completed" => {
                let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                    OxidraError::Session(format!(
                        "turn.completed at seq {} has no turn_id",
                        event.seq
                    ))
                })?;
                completion_seqs
                    .entry(turn_id.to_owned())
                    .or_default()
                    .push(event.seq);
            }
            _ => {}
        }
        if matches!(
            event.kind.as_str(),
            "response.completed"
                | "response.failed"
                | "response.aborted"
                | "turn.cancelled"
                | "agent.stalled"
                | "agent.limit_reached"
                | "context.limit_reached"
        ) {
            let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                OxidraError::Session(format!(
                    "{} at seq {} has no turn_id",
                    event.kind, event.seq
                ))
            })?;
            attempt_terminal_seqs
                .entry(turn_id.to_owned())
                .or_default()
                .push(event.seq);
        }
        if event.kind == "response.failed" {
            let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                OxidraError::Session(format!(
                    "response.failed at seq {} has no turn_id",
                    event.seq
                ))
            })?;
            failed_responses
                .entry(turn_id.to_owned())
                .or_default()
                .push(event);
        }
        if has_inline_turn_completion(event) {
            let turn_id = event.turn_id.as_deref().ok_or_else(|| {
                OxidraError::Session(format!(
                    "inline turn completion at seq {} has no turn_id",
                    event.seq
                ))
            })?;
            completion_seqs
                .entry(turn_id.to_owned())
                .or_default()
                .push(event.seq);
        }
    }

    for (turn_id, turn_limits) in &limits {
        let user_message_seq = users.get(turn_id).copied().ok_or_else(|| {
            OxidraError::Session(format!(
                "context.limit_reached references unknown turn {turn_id}"
            ))
        })?;
        for limit in turn_limits {
            if completion_seqs
                .get(turn_id)
                .is_some_and(|seqs| seqs.iter().any(|seq| *seq < limit.seq))
            {
                return Err(OxidraError::Session(format!(
                    "context.limit_reached at seq {} follows completion of turn {turn_id}",
                    limit.seq
                )));
            }
            validate_context_limit_binding(
                turn_id,
                user_message_seq,
                limit,
                failed_responses.get(turn_id).map(Vec::as_slice),
            )?;
        }
    }

    let mut abandons = HashMap::new();
    for event in events.iter().filter(|event| event.kind == "turn.abandoned") {
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.abandoned at seq {} has no turn_id",
                event.seq
            ))
        })?;
        if abandons.contains_key(turn_id) {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has duplicate turn.abandoned events"
            )));
        }
        let user_message_seq = event
            .data
            .get("user_message_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.abandoned at seq {} has no user_message_seq",
                    event.seq
                ))
            })?;
        if users.get(turn_id) != Some(&user_message_seq) {
            return Err(OxidraError::Session(format!(
                "turn.abandoned at seq {} does not reference turn {turn_id}'s user.message",
                event.seq
            )));
        }
        if completion_seqs.contains_key(turn_id) {
            return Err(OxidraError::Session(format!(
                "completed turn {turn_id} cannot be abandoned"
            )));
        }
        let limit = limits
            .get(turn_id)
            .and_then(|limits| {
                limits
                    .iter()
                    .copied()
                    .filter(|limit| limit.seq < event.seq)
                    .max_by_key(|limit| limit.seq)
            })
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.abandoned at seq {} is not preceded by context.limit_reached",
                    event.seq
                ))
            })?;
        validate_context_limit_binding(
            turn_id,
            user_message_seq,
            limit,
            failed_responses.get(turn_id).map(Vec::as_slice),
        )?;
        abandons.insert(
            turn_id.to_owned(),
            ValidatedAbandon {
                turn_id: turn_id.to_owned(),
                user_message_seq,
                limit_seq: limit.seq,
                abandon_seq: event.seq,
            },
        );
    }

    let mut retries = Vec::new();
    let mut retry_ids = HashSet::new();
    let mut previous_retry_seq: HashMap<String, u64> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "turn.retry_started")
    {
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.retry_started at seq {} has no turn_id",
                event.seq
            ))
        })?;
        let version = event
            .data
            .get("retry_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no retry_version",
                    event.seq
                ))
            })?;
        if version != 1 {
            return Err(OxidraError::Session(format!(
                "unsupported turn retry version {version} at seq {}",
                event.seq
            )));
        }
        let retry_id = event
            .data
            .get("retry_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no retry_id",
                    event.seq
                ))
            })?;
        if !retry_ids.insert(retry_id.to_owned()) {
            return Err(OxidraError::Session(format!(
                "duplicate turn retry id {retry_id}"
            )));
        }
        let user_message_seq = event
            .data
            .get("user_message_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no user_message_seq",
                    event.seq
                ))
            })?;
        if users.get(turn_id) != Some(&user_message_seq) {
            return Err(OxidraError::Session(format!(
                "turn.retry_started at seq {} does not reference turn {turn_id}'s user.message",
                event.seq
            )));
        }
        if completion_seqs
            .get(turn_id)
            .is_some_and(|seqs| seqs.iter().any(|seq| *seq < event.seq))
        {
            return Err(OxidraError::Session(format!(
                "completed turn {turn_id} cannot be retried"
            )));
        }
        if abandons
            .get(turn_id)
            .is_some_and(|abandon| abandon.abandon_seq < event.seq)
        {
            return Err(OxidraError::Session(format!(
                "abandoned turn {turn_id} cannot be retried"
            )));
        }
        let limit_seq = event
            .data
            .get("context_limit_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} has no context_limit_seq",
                    event.seq
                ))
            })?;
        let latest_limit = limits
            .get(turn_id)
            .and_then(|limits| {
                limits
                    .iter()
                    .copied()
                    .filter(|limit| limit.seq < event.seq)
                    .max_by_key(|limit| limit.seq)
            })
            .ok_or_else(|| {
                OxidraError::Session(format!(
                    "turn.retry_started at seq {} is not preceded by context.limit_reached",
                    event.seq
                ))
            })?;
        if limit_seq != latest_limit.seq {
            return Err(OxidraError::Session(format!(
                "turn.retry_started at seq {} does not reference the latest context limit",
                event.seq
            )));
        }
        validate_context_limit_binding(
            turn_id,
            user_message_seq,
            latest_limit,
            failed_responses.get(turn_id).map(Vec::as_slice),
        )?;
        if let Some(previous) = previous_retry_seq.get(turn_id) {
            let previous_was_settled = attempt_terminal_seqs
                .get(turn_id)
                .is_some_and(|seqs| seqs.iter().any(|seq| *seq > *previous && *seq < event.seq));
            if limit_seq <= *previous && !previous_was_settled {
                return Err(OxidraError::Session(format!(
                    "turn.retry_started at seq {} duplicates an undispatched retry intent",
                    event.seq
                )));
            }
        }
        previous_retry_seq.insert(turn_id.to_owned(), event.seq);
        retries.push(ValidatedRetry {
            retry_id: retry_id.to_owned(),
            turn_id: turn_id.to_owned(),
            user_message_seq,
            limit_seq,
            retry_seq: event.seq,
        });
    }

    Ok(ValidatedTurnRecovery { abandons, retries })
}

fn validate_context_limit_binding(
    turn_id: &str,
    user_message_seq: u64,
    limit: &JournalEvent,
    failed_responses: Option<&[&JournalEvent]>,
) -> Result<()> {
    if user_message_seq >= limit.seq {
        return Err(OxidraError::Session(format!(
            "context.limit_reached at seq {} does not follow turn {turn_id}'s user.message",
            limit.seq
        )));
    }
    let response_attempt_id = limit
        .data
        .get("response_attempt_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let provider_reported = limit.data.get("source").and_then(Value::as_str) == Some("provider");
    if provider_reported && response_attempt_id.is_none() {
        return Err(OxidraError::Session(format!(
            "provider context.limit_reached at seq {} has no response_attempt_id",
            limit.seq
        )));
    }
    if let Some(response_attempt_id) = response_attempt_id {
        let bound = failed_responses.is_some_and(|responses| {
            responses.iter().any(|response| {
                response.seq > user_message_seq
                    && response.seq < limit.seq
                    && response
                        .data
                        .get("response_attempt_id")
                        .and_then(Value::as_str)
                        == Some(response_attempt_id)
            })
        });
        if !bound {
            return Err(OxidraError::Session(format!(
                "context.limit_reached at seq {} is not bound to response.failed attempt {response_attempt_id}",
                limit.seq
            )));
        }
    }
    Ok(())
}

/// Segment user turns without changing or projecting any journal content.
pub fn segment_turns(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    segment_turns_for_version(TURN_BOUNDARY_VALIDATOR_VERSION, events)
}

/// Resolve the historical recovery language claimed by each user turn.
///
/// The owning `user.message` is the only authority for this choice. A later
/// completion written by a newer binary cannot retroactively strengthen the
/// recovery grammar of an already-started turn. Likewise,
/// `compaction.*.turn_boundary_validator_version` records the frozen reducer
/// used to build that compaction artifact; it does not upgrade the language of
/// every historical turn covered by the checkpoint.
fn resolve_user_turn_boundary_versions(events: &[JournalEvent]) -> Result<HashMap<String, u32>> {
    let mut turn_versions = HashMap::new();
    for event in events.iter().filter(|event| event.kind == "user.message") {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        let version = event
            .data
            .get("turn_boundary_version")
            .map(|value| parse_turn_boundary_claim(event.seq, "turn boundary", value))
            .transpose()?
            .unwrap_or(1);
        if turn_versions.insert(turn_id.to_owned(), version).is_some() {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one user.message"
            )));
        }
    }
    Ok(turn_versions)
}

fn parse_turn_boundary_claim(seq: u64, label: &str, value: &Value) -> Result<u32> {
    let version = value.as_u64().ok_or_else(|| {
        OxidraError::Session(format!(
            "{label} version at seq {seq} is not an unsigned integer"
        ))
    })?;
    let version = u32::try_from(version).map_err(|_| {
        OxidraError::Session(format!(
            "unsupported {label} version {version} at seq {seq}"
        ))
    })?;
    if !(1..=TURN_BOUNDARY_VALIDATOR_VERSION).contains(&version) {
        return Err(OxidraError::Session(format!(
            "unsupported {label} version {version} at seq {seq}"
        )));
    }
    Ok(version)
}

fn last_response_event_seq_for_turn_span(events: &[JournalEvent], turn: &TurnSpan) -> Option<u64> {
    events
        .get(turn.start_index..turn.end_index_exclusive)
        .into_iter()
        .flatten()
        .filter(|event| event.turn_id.as_deref() == Some(turn.turn_id.as_str()))
        .filter(|event| is_response_lifecycle_v1(&event.kind))
        .map(|event| event.seq)
        .next_back()
}

/// Rebuild turn boundaries using an immutable historical reducer.
/// Published match arms must not be changed; add a new version instead.
pub(crate) fn segment_turns_for_version(
    version: u32,
    events: &[JournalEvent],
) -> Result<Vec<TurnSpan>> {
    match version {
        1 => segment_turns_v1(events),
        2 => segment_turns_v2(events),
        3 => segment_turns_v3(events),
        4 => segment_turns_v4(events),
        5 => segment_turns_v5(events),
        6 => segment_turns_v6(events),
        7 => segment_turns_v7(events),
        8 => segment_turns_v8(events),
        _ => Err(OxidraError::Session(format!(
            "unsupported turn boundary reducer version {version}"
        ))),
    }
}

// v2 冻结为 40e7930 的字面语义；后续修正只能新增版本。
fn segment_turns_v2(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    let recovery = validate_turn_recovery_v2(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v2_for_v1(event)?;
        if event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed" | "response.aborted" | "context.limit_reached"
                    )
            })
        {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_v1(&normalized)
}

fn normalize_boundary_version_v2_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1 | 2) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1 | 2) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn segment_turns_v3(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    let recovery = validate_turn_recovery_v3(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v3_for_v1(event)?;
        if event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            })
        {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_v1(&normalized)
}

fn normalize_boundary_version_v3_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=3) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=3) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn segment_turns_v4(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    let recovery = validate_turn_recovery_v3(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v4_for_v1(event)?;
        if event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            })
        {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_base(&normalized, LegacyCompletionSeq::NextUserEvidence)
}

fn segment_turns_v5(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    let recovery = validate_turn_recovery_v3(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let budget_retry_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v5_for_v1(event)?;
        let context_retry_supersedes = event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            });
        let budget_retry_supersedes =
            event.kind == "agent.limit_reached" && budget_retry_limit_seqs.contains(&event.seq);
        if context_retry_supersedes || budget_retry_supersedes {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_base(&normalized, LegacyCompletionSeq::NextUserEvidence)
}

fn segment_turns_v6(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    validate_mcp_call_chain_for_version(TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V6, events)?;
    let recovery = validate_turn_recovery_v3(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let budget_retry_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v6_for_v1(event)?;
        let context_retry_supersedes = event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            });
        let budget_retry_supersedes =
            event.kind == "agent.limit_reached" && budget_retry_limit_seqs.contains(&event.seq);
        if context_retry_supersedes || budget_retry_supersedes {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_base(&normalized, LegacyCompletionSeq::NextUserEvidence)
}

fn segment_turns_v7(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    validate_mcp_call_chain_through_version(
        TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V7,
        events,
    )?;
    let recovery = validate_turn_recovery_v3(events)?;
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let budget_retry_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v7_for_v1(event)?;
        let context_retry_supersedes = event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            });
        let budget_retry_supersedes =
            event.kind == "agent.limit_reached" && budget_retry_limit_seqs.contains(&event.seq);
        if context_retry_supersedes || budget_retry_supersedes {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_base(&normalized, LegacyCompletionSeq::NextUserEvidence)
}

fn segment_turns_v8(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    validate_mcp_call_chain_through_version(
        TURN_BOUNDARY_MCP_CALL_CHAIN_VALIDATOR_VERSION_V8,
        events,
    )?;
    let turn_versions = resolve_user_turn_boundary_versions(events)?;
    // v8 is the first turn reducer that fixes recovery-language ownership.
    // Structural rules stay current for the journal, while each user.message
    // selects the v2/v3 recovery grammar for its own turn. Versions v1-v7
    // remain literal and must never learn this dispatch rule.
    let recovery = validate_turn_recovery_for_versions(events, &turn_versions)?;
    let legacy_pre_user = legacy_pre_user_recovery_turns(events, &turn_versions);
    let mut turns = segment_turns_v8_with_recovery(events, recovery, &legacy_pre_user)?;

    // Recovery ownership must not retroactively change the historical
    // completion evidence selected by the owning user turn: reducers v1-v3
    // use the last response event, while v4+ use the next user event.
    for turn in &mut turns {
        let version = turn_versions.get(&turn.turn_id).copied().unwrap_or(1);
        if version < 4
            && matches!(
                turn.state,
                TurnState::Complete(CompletionEvidence::LegacyNextUser)
            )
        {
            turn.completion_seq = last_response_event_seq_for_turn_span(events, turn);
        }
    }
    Ok(turns)
}

fn segment_turns_v8_with_recovery(
    events: &[JournalEvent],
    recovery: ValidatedTurnRecovery,
    legacy_pre_user_recovery_turns: &HashSet<String>,
) -> Result<Vec<TurnSpan>> {
    let latest_retry_by_turn =
        recovery
            .retries
            .iter()
            .fold(HashMap::<String, u64>::new(), |mut latest, retry| {
                latest
                    .entry(retry.turn_id.clone())
                    .and_modify(|seq| *seq = (*seq).max(retry.retry_seq))
                    .or_insert(retry.retry_seq);
                latest
            });
    let budget_retry_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        normalize_boundary_version_v8_for_v1(event)?;
        let context_retry_supersedes = event
            .turn_id
            .as_ref()
            .and_then(|turn_id| latest_retry_by_turn.get(turn_id))
            .is_some_and(|retry_seq| {
                event.seq < *retry_seq
                    && matches!(
                        event.kind.as_str(),
                        "response.failed"
                            | "response.aborted"
                            | "turn.cancelled"
                            | "agent.stalled"
                            | "agent.limit_reached"
                            | "context.limit_reached"
                    )
            });
        let budget_retry_supersedes =
            event.kind == "agent.limit_reached" && budget_retry_limit_seqs.contains(&event.seq);
        if context_retry_supersedes || budget_retry_supersedes {
            event.kind = "turn.retry_superseded".to_owned();
        }
    }
    segment_turns_base_with_pre_user_recovery(
        &normalized,
        LegacyCompletionSeq::NextUserEvidence,
        legacy_pre_user_recovery_turns,
    )
}

fn normalize_boundary_version_v4_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=4) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=4) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn normalize_boundary_version_v5_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=5) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=5) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn normalize_boundary_version_v6_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=6) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=6) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn normalize_boundary_version_v7_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=7) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=7) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn normalize_boundary_version_v8_for_v1(event: &mut JournalEvent) -> Result<()> {
    let seq = event.seq;
    if let Some(version) = direct_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=8) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = inline_turn_boundary_version_mut(event) {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                seq
            ))
        })?;
        if !matches!(value, 1..=8) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum LegacyCompletionSeq {
    LastResponse,
    NextUserEvidence,
}

fn segment_turns_v1(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
    segment_turns_base(events, LegacyCompletionSeq::LastResponse)
}

fn segment_turns_base(
    events: &[JournalEvent],
    legacy_completion_seq: LegacyCompletionSeq,
) -> Result<Vec<TurnSpan>> {
    segment_turns_base_with_pre_user_recovery(events, legacy_completion_seq, &HashSet::new())
}

fn segment_turns_base_with_pre_user_recovery(
    events: &[JournalEvent],
    legacy_completion_seq: LegacyCompletionSeq,
    legacy_pre_user_recovery_turns: &HashSet<String>,
) -> Result<Vec<TurnSpan>> {
    let mut starts = Vec::new();
    let mut seen_turn_ids = HashSet::new();
    for (index, event) in events.iter().enumerate() {
        if event.kind != "user.message" {
            continue;
        }
        let turn_id = event.turn_id.as_deref().ok_or_else(|| {
            OxidraError::Session(format!("user.message at seq {} has no turn_id", event.seq))
        })?;
        if !seen_turn_ids.insert(turn_id.to_owned()) {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one user.message"
            )));
        }
        starts.push((index, turn_id.to_owned()));
    }

    let ranges = starts
        .iter()
        .enumerate()
        .map(|(position, (start, turn_id))| {
            let end = starts
                .get(position + 1)
                .map(|(index, _)| *index)
                .unwrap_or(events.len());
            (turn_id.clone(), (*start, end))
        })
        .collect::<HashMap<_, _>>();

    for (index, event) in events.iter().enumerate() {
        let Some(turn_id) = event.turn_id.as_deref() else {
            if is_turn_scoped_v1(&event.kind) {
                return Err(OxidraError::Session(format!(
                    "{} at seq {} has no turn_id",
                    event.kind, event.seq
                )));
            }
            continue;
        };
        let Some((start, end)) = ranges.get(turn_id) else {
            if is_turn_scoped_v1(&event.kind) {
                return Err(OxidraError::Session(format!(
                    "{} at seq {} references unknown turn {turn_id}",
                    event.kind, event.seq
                )));
            }
            continue;
        };
        if index < *start
            && legacy_pre_user_recovery_turns.contains(turn_id)
            && event.kind == "context.limit_reached"
        {
            continue;
        }
        if index < *start || index >= *end {
            return Err(OxidraError::Session(format!(
                "event at seq {} appears outside turn {turn_id}",
                event.seq
            )));
        }
    }

    let mut turns = Vec::with_capacity(starts.len());
    for (position, (start_index, turn_id)) in starts.iter().enumerate() {
        let end_index_exclusive = starts
            .get(position + 1)
            .map(|(index, _)| *index)
            .unwrap_or(events.len());
        let user_event = &events[*start_index];
        let tagged = boundary_version(user_event)?.is_some();
        let turn_events = events
            .iter()
            .enumerate()
            .filter(|(index, event)| {
                event.turn_id.as_deref() == Some(turn_id.as_str())
                    && ((*index >= *start_index && *index < end_index_exclusive)
                        || (legacy_pre_user_recovery_turns.contains(turn_id)
                            && *index < *start_index
                            && event.kind == "context.limit_reached"))
            })
            .map(|(_, event)| event)
            .collect::<Vec<_>>();
        let markers = turn_events
            .iter()
            .copied()
            .filter(|event| event.kind == "turn.completed")
            .collect::<Vec<_>>();
        if markers.len() > 1 {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one turn.completed marker"
            )));
        }
        let inline_completions = turn_events
            .iter()
            .copied()
            .filter(|event| has_inline_turn_completion(event))
            .collect::<Vec<_>>();
        if inline_completions.len() > 1 {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one inline completion boundary"
            )));
        }

        let calls = validate_call_outputs(&turn_events)?;
        let next_user_seq = starts
            .get(position + 1)
            .map(|(next_start_index, _)| events[*next_start_index].seq);
        let has_next_user = next_user_seq.is_some();
        let inline_completion = inline_completions.first().copied();
        if let Some(response) = inline_completion {
            validate_inline_completion(user_event, response, &turn_events, &calls)?;
        }
        let (state, covers_through_seq, completion_seq) = if let Some(marker) =
            markers.first().copied()
        {
            validate_completed_marker(user_event, marker, &turn_events, &calls)?;
            if let Some(response) = inline_completion {
                let marker_response_seq = required_u64(marker, "final_response_seq")?;
                if marker_response_seq != response.seq {
                    return Err(OxidraError::Session(format!(
                        "turn.completed at seq {} conflicts with inline completion at seq {}",
                        marker.seq, response.seq
                    )));
                }
            }
            (
                TurnState::Complete(CompletionEvidence::ExplicitMarker),
                marker.seq,
                Some(inline_completion.map_or(marker.seq, |response| response.seq)),
            )
        } else if let Some(response) = inline_completion {
            (
                TurnState::Complete(CompletionEvidence::InlineResponse),
                response.seq,
                Some(response.seq),
            )
        } else {
            let state = classify_unmarked_turn(&turn_events, tagged, has_next_user, &calls);
            let covers_through_seq = if end_index_exclusive > *start_index {
                events[end_index_exclusive - 1].seq
            } else {
                user_event.seq
            };
            let completion_seq = match state {
                TurnState::Complete(CompletionEvidence::LegacyNextUser) => {
                    match legacy_completion_seq {
                        LegacyCompletionSeq::LastResponse => last_response_event_seq(&turn_events),
                        LegacyCompletionSeq::NextUserEvidence => next_user_seq,
                    }
                }
                TurnState::Complete(_) => last_response_event_seq(&turn_events),
                _ => None,
            };
            (state, covers_through_seq, completion_seq)
        };
        let cut_safe = match state {
            TurnState::Complete(_) => true,
            TurnState::Cancelled
            | TurnState::Aborted
            | TurnState::Failed
            | TurnState::Stalled
            | TurnState::LimitReached => has_next_user && calls.is_resolved(),
            TurnState::Incomplete => has_next_user && calls.is_resolved(),
            TurnState::InDoubt | TurnState::OpenTail => false,
        };

        turns.push(TurnSpan {
            turn_id: turn_id.clone(),
            start_index: *start_index,
            end_index_exclusive,
            covers_from_seq: user_event.seq,
            covers_through_seq,
            state,
            completion_seq,
            cut_safe,
        });
    }
    Ok(turns)
}

/// Return complete cutoffs in the contiguous cut-safe prefix.
pub fn complete_prefix_candidates(events: &[JournalEvent]) -> Result<Vec<CompletePrefix>> {
    complete_prefix_candidates_from_turns(segment_turns(events)?)
}

/// Rebuild complete-prefix cutoffs using an immutable historical reducer.
pub(crate) fn complete_prefix_candidates_for_version(
    version: u32,
    events: &[JournalEvent],
) -> Result<Vec<CompletePrefix>> {
    complete_prefix_candidates_from_turns(segment_turns_for_version(version, events)?)
}

fn complete_prefix_candidates_from_turns(turns: Vec<TurnSpan>) -> Result<Vec<CompletePrefix>> {
    let mut candidates = Vec::new();
    let mut complete_turns = 0;
    for turn in turns {
        if !turn.cut_safe {
            break;
        }
        if matches!(turn.state, TurnState::Complete(_)) {
            complete_turns += 1;
            candidates.push(CompletePrefix {
                turn_count: complete_turns,
                covers_through_seq: turn.covers_through_seq,
            });
        }
    }
    Ok(candidates)
}

// These classifications are part of turn reducer v1. Keep them local so a new
// journal event added to the current reducer cannot change historical cutoffs.
fn is_tool_terminal_v1(kind: &str) -> bool {
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

fn is_response_lifecycle_v1(kind: &str) -> bool {
    matches!(
        kind,
        "response.started" | "response.completed" | "response.failed" | "response.aborted"
    )
}

fn is_turn_scoped_v1(kind: &str) -> bool {
    matches!(
        kind,
        "user.message"
            | "turn.completed"
            | "turn.cancelled"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
            | "tool.started"
            | "tool.in_doubt"
    ) || is_response_lifecycle_v1(kind)
        || is_tool_terminal_v1(kind)
}

fn boundary_version(event: &JournalEvent) -> Result<Option<u64>> {
    let Some(value) = event.data.get("turn_boundary_version") else {
        return Ok(None);
    };
    let version = value.as_u64().ok_or_else(|| {
        OxidraError::Session(format!(
            "turn boundary version at seq {} is not an unsigned integer",
            event.seq
        ))
    })?;
    if version != 1 {
        return Err(OxidraError::Session(format!(
            "unsupported turn boundary version {version} at seq {}",
            event.seq
        )));
    }
    Ok(Some(version))
}

fn validate_completed_marker(
    user_event: &JournalEvent,
    marker: &JournalEvent,
    turn_events: &[&JournalEvent],
    calls: &CallValidation,
) -> Result<()> {
    if boundary_version(marker)? != Some(1) {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} has no boundary version",
            marker.seq
        )));
    }
    let covers_from_seq = required_u64(marker, "covers_from_seq")?;
    let final_response_seq = required_u64(marker, "final_response_seq")?;
    let covers_through_seq = required_u64(marker, "covers_through_seq")?;
    if covers_from_seq != user_event.seq || covers_through_seq != marker.seq {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} has inconsistent coverage",
            marker.seq
        )));
    }
    let final_response = turn_events
        .iter()
        .copied()
        .find(|event| event.seq == final_response_seq)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "turn.completed at seq {} references missing response seq {final_response_seq}",
                marker.seq
            ))
        })?;
    if final_response.kind != "response.completed"
        || final_response.seq >= marker.seq
        || response_has_function_call(final_response)
    {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} does not reference a final response",
            marker.seq
        )));
    }
    let last_response_event_seq = turn_events
        .iter()
        .rev()
        .find(|event| is_response_lifecycle_v1(&event.kind))
        .map(|event| event.seq);
    if last_response_event_seq != Some(final_response_seq) {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} does not reference the last response terminal event",
            marker.seq
        )));
    }
    if turn_events
        .iter()
        .any(|event| event.seq > marker.seq || disqualifies_completion(event))
    {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} conflicts with another turn event",
            marker.seq
        )));
    }
    if !calls.is_resolved() {
        return Err(OxidraError::Session(format!(
            "turn.completed at seq {} leaves unresolved tool calls",
            marker.seq
        )));
    }
    Ok(())
}

fn validate_inline_completion(
    user_event: &JournalEvent,
    response: &JournalEvent,
    turn_events: &[&JournalEvent],
    calls: &CallValidation,
) -> Result<()> {
    let completion = response
        .data
        .get("turn_completion")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "response.completed at seq {} has an invalid inline completion boundary",
                response.seq
            ))
        })?;
    let version = completion
        .get("turn_boundary_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "inline completion at seq {} has no boundary version",
                response.seq
            ))
        })?;
    if version != 1 {
        return Err(OxidraError::Session(format!(
            "unsupported turn boundary version {version} at seq {}",
            response.seq
        )));
    }
    let field = |name: &str| completion.get(name).and_then(Value::as_u64);
    if field("covers_from_seq") != Some(user_event.seq)
        || field("final_response_seq") != Some(response.seq)
        || field("covers_through_seq") != Some(response.seq)
    {
        return Err(OxidraError::Session(format!(
            "inline completion at seq {} has inconsistent coverage",
            response.seq
        )));
    }
    if response_has_function_call(response)
        || last_response_event_seq(turn_events) != Some(response.seq)
        || turn_events.iter().any(disqualifies_completion)
        || !calls.is_resolved()
    {
        return Err(OxidraError::Session(format!(
            "inline completion at seq {} does not describe a complete turn",
            response.seq
        )));
    }
    Ok(())
}

fn classify_unmarked_turn(
    turn_events: &[&JournalEvent],
    tagged: bool,
    has_next_user: bool,
    calls: &CallValidation,
) -> TurnState {
    if calls.unresolved_in_doubt
        || turn_events
            .iter()
            .any(|event| event.kind == "tool.in_doubt")
            && calls.pending_count > 0
    {
        return TurnState::InDoubt;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "turn.cancelled")
    {
        return TurnState::Cancelled;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "response.aborted")
    {
        return TurnState::Aborted;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "response.failed")
    {
        return TurnState::Failed;
    }
    if turn_events
        .iter()
        .any(|event| event.kind == "agent.stalled")
    {
        return TurnState::Stalled;
    }
    if turn_events.iter().any(|event| {
        matches!(
            event.kind.as_str(),
            "agent.limit_reached" | "context.limit_reached"
        )
    }) {
        return TurnState::LimitReached;
    }
    if !tagged && has_next_user && calls.is_resolved() && last_response_is_final(turn_events) {
        return TurnState::Complete(CompletionEvidence::LegacyNextUser);
    }
    if has_next_user {
        TurnState::Incomplete
    } else {
        TurnState::OpenTail
    }
}

fn last_response_is_final(turn_events: &[&JournalEvent]) -> bool {
    turn_events
        .iter()
        .rev()
        .copied()
        .find(|event| is_response_lifecycle_v1(&event.kind))
        .is_some_and(|event| {
            event.kind == "response.completed" && !response_has_function_call(event)
        })
}

fn last_response_event_seq(turn_events: &[&JournalEvent]) -> Option<u64> {
    turn_events
        .iter()
        .rev()
        .find(|event| is_response_lifecycle_v1(&event.kind))
        .map(|event| event.seq)
}

fn disqualifies_completion(event: &&JournalEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "turn.cancelled"
            | "response.aborted"
            | "response.failed"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
    )
}

#[derive(Default)]
struct CallValidation {
    pending_count: usize,
    unresolved_in_doubt: bool,
    uncertain: bool,
}

impl CallValidation {
    fn is_resolved(&self) -> bool {
        self.pending_count == 0 && !self.unresolved_in_doubt && !self.uncertain
    }
}

/// Rebuild the Provider request slot from the durable journal prefix.
///
/// Unlike a final `TurnSpan` boolean, this reducer validates every transition:
/// only one response attempt may be active, a later request cannot start until
/// all calls from the previous response are settled, and a retry must be a
/// validated recovery transition. Published match arms are immutable; add a
/// new version when these rules change.
pub(crate) fn provider_request_slot_state_for_version(
    version: u32,
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    match version {
        1 => provider_request_slot_state_v1(events, turn_id),
        2 => provider_request_slot_state_v2(events, turn_id),
        3 => provider_request_slot_state_v3(events, turn_id),
        4 => provider_request_slot_state_v4(events, turn_id),
        5 => provider_request_slot_state_v5(events, turn_id),
        _ => Err(OxidraError::Session(format!(
            "unsupported Provider request-slot reducer version {version}"
        ))),
    }
}

fn provider_request_slot_state_v5(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    validate_mcp_call_chain_through_version(
        PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V5,
        events,
    )?;
    provider_request_slot_state_v2(events, turn_id)
}

fn provider_request_slot_state_v4(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    validate_mcp_call_chain_through_version(
        PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V4,
        events,
    )?;
    provider_request_slot_state_v2(events, turn_id)
}

fn provider_request_slot_state_v3(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    validate_mcp_call_chain_for_version(
        PROVIDER_REQUEST_SLOT_MCP_CALL_CHAIN_VALIDATOR_VERSION_V3,
        events,
    )?;
    provider_request_slot_state_v2(events, turn_id)
}

fn provider_request_slot_state_v2(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    let superseded_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .filter(|retry| retry.boundary.turn_id == turn_id)
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        if event.kind == "agent.limit_reached" && superseded_limit_seqs.contains(&event.seq) {
            event.kind = "turn.budget_retry_superseded".to_owned();
        }
    }
    provider_request_slot_state_v1(&normalized, turn_id)
}

/// Validate the frozen v2 Provider slot reducer for a set of turns without
/// rerunning its global journal reducers or cloning the complete journal once
/// per turn. Recovery uses this batch form for large legacy MCP responses.
pub(crate) fn validate_provider_request_slots_v2(
    events: &[JournalEvent],
    turn_ids: &[String],
) -> Result<()> {
    let mut seen_turn_ids = HashSet::new();
    let ordered_turn_ids = turn_ids
        .iter()
        .map(String::as_str)
        .filter(|turn_id| seen_turn_ids.insert(*turn_id))
        .collect::<Vec<_>>();
    if ordered_turn_ids.is_empty() {
        return Ok(());
    }
    let turn_id_membership = ordered_turn_ids.iter().copied().collect::<HashSet<_>>();
    let superseded_limit_seqs = validate_provider_budget_retries_v1(events)?
        .into_iter()
        .filter(|retry| turn_id_membership.contains(retry.boundary.turn_id.as_str()))
        .map(|retry| retry.limit_seq)
        .collect::<HashSet<_>>();
    let mut normalized = events.to_vec();
    for event in &mut normalized {
        if event.kind == "agent.limit_reached" && superseded_limit_seqs.contains(&event.seq) {
            event.kind = "turn.budget_retry_superseded".to_owned();
        }
    }
    validate_provider_slot_event_turn_ids(&normalized)?;
    let mut scoped = HashMap::<&str, Vec<JournalEvent>>::new();
    for event in &normalized {
        let Some(turn_id) = event.turn_id.as_deref() else {
            continue;
        };
        if turn_id_membership.contains(turn_id) {
            scoped.entry(turn_id).or_default().push(event.clone());
        }
    }
    let scoped_recovery_events = ordered_turn_ids
        .iter()
        .flat_map(|turn_id| scoped.get(turn_id).into_iter().flatten().cloned())
        .collect::<Vec<_>>();
    let recovery = validate_turn_recovery_v3(&scoped_recovery_events)?;
    for turn_id in ordered_turn_ids {
        provider_request_slot_state_v1_with_recovery(
            scoped.get(turn_id).map(Vec::as_slice).unwrap_or_default(),
            turn_id,
            &recovery,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ProviderSlotCall {
    call_id: String,
    started_seq: Option<u64>,
    in_doubt: bool,
    terminal: bool,
}

fn provider_request_slot_state_v1(
    events: &[JournalEvent],
    turn_id: &str,
) -> Result<ProviderRequestSlotState> {
    validate_provider_slot_event_turn_ids(events)?;
    // Slot v1 deliberately keeps recovery-v3 semantics for the target turn,
    // but it is a turn-scoped reducer. Running recovery v3 over the complete
    // journal retroactively reinterprets unrelated, legal v2 recovery rows
    // whenever a later turn asks for a Provider slot.
    let scoped_recovery_events = events
        .iter()
        .filter(|event| event.turn_id.as_deref() == Some(turn_id))
        .cloned()
        .collect::<Vec<_>>();
    let recovery = validate_turn_recovery_v3(&scoped_recovery_events)?;
    provider_request_slot_state_v1_with_recovery(events, turn_id, &recovery)
}

fn validate_provider_slot_event_turn_ids(events: &[JournalEvent]) -> Result<()> {
    for event in events {
        if is_provider_slot_event_kind(&event.kind) && event.turn_id.is_none() {
            return Err(OxidraError::Session(format!(
                "{} at seq {} has no turn_id",
                event.kind, event.seq
            )));
        }
    }
    Ok(())
}

fn provider_request_slot_state_v1_with_recovery(
    events: &[JournalEvent],
    turn_id: &str,
    recovery: &ValidatedTurnRecovery,
) -> Result<ProviderRequestSlotState> {
    let validated_retry_seqs = recovery
        .retries
        .iter()
        .filter(|retry| retry.turn_id == turn_id)
        .map(|retry| retry.retry_seq)
        .collect::<HashSet<_>>();

    let mut saw_user = false;
    let mut state = ProviderRequestSlotState::Ready;
    let mut active_attempt = None::<String>;
    let mut seen_attempts = HashSet::<String>::new();
    let mut calls = Vec::<ProviderSlotCall>::new();
    let mut seen_call_ids = HashSet::<String>::new();
    let mut call_indexes = HashMap::<String, usize>::new();
    let mut unresolved_calls = 0usize;

    for event in events
        .iter()
        .filter(|event| event.turn_id.as_deref() == Some(turn_id))
    {
        match event.kind.as_str() {
            "user.message" => {
                if saw_user {
                    return Err(OxidraError::Session(format!(
                        "turn {turn_id} has more than one user.message"
                    )));
                }
                saw_user = true;
            }
            "response.started" => {
                require_slot_user(saw_user, event, turn_id)?;
                if state != ProviderRequestSlotState::Ready
                    || active_attempt.is_some()
                    || unresolved_calls != 0
                {
                    return Err(OxidraError::Session(format!(
                        "response.started at seq {} cannot acquire turn {turn_id}'s Provider request slot from state {state:?}",
                        event.seq
                    )));
                }
                let attempt_id = required_response_attempt_id(event)?;
                if !seen_attempts.insert(attempt_id.to_owned()) {
                    return Err(OxidraError::Session(format!(
                        "duplicate response attempt id {attempt_id} at seq {}",
                        event.seq
                    )));
                }
                active_attempt = Some(attempt_id.to_owned());
                state = ProviderRequestSlotState::ResponseInFlight;
            }
            "response.completed" | "response.failed" | "response.aborted" => {
                require_slot_user(saw_user, event, turn_id)?;
                let attempt_id = required_response_attempt_id(event)?;
                if state != ProviderRequestSlotState::ResponseInFlight
                    || active_attempt.as_deref() != Some(attempt_id)
                {
                    return Err(OxidraError::Session(format!(
                        "{} at seq {} does not terminate the active response attempt for turn {turn_id}",
                        event.kind, event.seq
                    )));
                }
                active_attempt = None;
                if event.kind == "response.completed" {
                    let call_ids = response_function_call_ids(event)?;
                    if call_ids.is_empty() {
                        state = ProviderRequestSlotState::Terminal;
                    } else {
                        for call_id in call_ids {
                            if !seen_call_ids.insert(call_id.clone()) {
                                return Err(OxidraError::Session(format!(
                                    "duplicate function call id {call_id} at seq {}",
                                    event.seq
                                )));
                            }
                            calls.push(ProviderSlotCall {
                                call_id: call_id.clone(),
                                started_seq: None,
                                in_doubt: false,
                                terminal: false,
                            });
                            call_indexes.insert(call_id, calls.len() - 1);
                            unresolved_calls =
                                unresolved_calls.checked_add(1).ok_or_else(|| {
                                    OxidraError::Session(format!(
                                        "turn {turn_id} Provider call count overflow"
                                    ))
                                })?;
                        }
                        state = ProviderRequestSlotState::AwaitingTools;
                    }
                } else {
                    state = ProviderRequestSlotState::Terminal;
                }
            }
            "tool.started" => {
                require_slot_user(saw_user, event, turn_id)?;
                require_awaiting_tools(state, event, turn_id)?;
                let call_id = required_call_id(event)?;
                let Some(index) = call_indexes.get(call_id).copied() else {
                    return Err(OxidraError::Session(format!(
                        "tool.started at seq {} does not match an unstarted call {call_id}",
                        event.seq
                    )));
                };
                let call = &mut calls[index];
                if call.started_seq.is_some() || call.terminal {
                    return Err(OxidraError::Session(format!(
                        "tool.started at seq {} does not match an unstarted call {call_id}",
                        event.seq
                    )));
                }
                call.started_seq = Some(event.seq);
            }
            "tool.in_doubt" => {
                require_slot_user(saw_user, event, turn_id)?;
                require_awaiting_tools(state, event, turn_id)?;
                let index = slot_call_index(&calls, &call_indexes, event, SlotCallMatch::Started)?;
                if calls[index].in_doubt {
                    return Err(OxidraError::Session(format!(
                        "tool.in_doubt at seq {} duplicates call {}",
                        event.seq, calls[index].call_id
                    )));
                }
                calls[index].in_doubt = true;
            }
            kind if is_tool_terminal_v1(kind) => {
                require_slot_user(saw_user, event, turn_id)?;
                require_awaiting_tools(state, event, turn_id)?;
                let match_kind = if kind == "tool.in_doubt_resolved" {
                    SlotCallMatch::InDoubt
                } else if kind.starts_with("tool.skipped_due_to_") {
                    SlotCallMatch::Unstarted
                } else {
                    SlotCallMatch::AnyPending
                };
                let index = slot_call_index(&calls, &call_indexes, event, match_kind)?;
                if kind != "tool.in_doubt_resolved" && calls[index].in_doubt {
                    return Err(OxidraError::Session(format!(
                        "{} at seq {} cannot settle in-doubt call {} without explicit resolution",
                        event.kind, event.seq, calls[index].call_id
                    )));
                }
                calls[index].terminal = true;
                calls[index].in_doubt = false;
                unresolved_calls = unresolved_calls.checked_sub(1).ok_or_else(|| {
                    OxidraError::Session(format!(
                        "{} at seq {} underflows turn {turn_id}'s pending call count",
                        event.kind, event.seq
                    ))
                })?;
                if unresolved_calls == 0 {
                    state = ProviderRequestSlotState::Ready;
                }
            }
            "turn.retry_started" => {
                require_slot_user(saw_user, event, turn_id)?;
                if !validated_retry_seqs.contains(&event.seq) {
                    return Err(OxidraError::Session(format!(
                        "turn.retry_started at seq {} is absent from the validated recovery reducer",
                        event.seq
                    )));
                }
                if state != ProviderRequestSlotState::Terminal
                    || active_attempt.is_some()
                    || unresolved_calls != 0
                {
                    return Err(OxidraError::Session(format!(
                        "turn.retry_started at seq {} cannot reacquire turn {turn_id}'s Provider request slot from state {state:?}",
                        event.seq
                    )));
                }
                state = ProviderRequestSlotState::Ready;
            }
            "turn.cancelled"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
            | "turn.completed" => {
                require_slot_user(saw_user, event, turn_id)?;
                if active_attempt.is_some()
                    || state == ProviderRequestSlotState::ResponseInFlight
                    || unresolved_calls != 0
                {
                    return Err(OxidraError::Session(format!(
                        "{} at seq {} terminates turn {turn_id} while its Provider request slot is unsettled",
                        event.kind, event.seq
                    )));
                }
                state = ProviderRequestSlotState::Terminal;
            }
            _ => {}
        }
    }

    if !saw_user {
        return Err(OxidraError::Session(format!(
            "Provider request-slot reducer cannot find turn {turn_id}'s user.message"
        )));
    }
    Ok(state)
}

pub(crate) fn is_provider_slot_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "response.started"
            | "response.completed"
            | "response.failed"
            | "response.aborted"
            | "turn.retry_started"
            | "turn.cancelled"
            | "agent.stalled"
            | "agent.limit_reached"
            | "context.limit_reached"
            | "turn.completed"
            | "tool.started"
            | "tool.in_doubt"
            | "tool.completed"
            | "tool.cancelled"
            | "tool.in_doubt_resolved"
            | "tool.skipped_due_to_cancel"
            | "tool.skipped_due_to_in_doubt"
            | "tool.skipped_due_to_limit"
            | "tool.skipped_due_to_stalled"
            | "tool.skipped_due_to_recovery"
    )
}

fn require_slot_user(saw_user: bool, event: &JournalEvent, turn_id: &str) -> Result<()> {
    if saw_user {
        return Ok(());
    }
    Err(OxidraError::Session(format!(
        "{} at seq {} precedes turn {turn_id}'s user.message",
        event.kind, event.seq
    )))
}

fn require_awaiting_tools(
    state: ProviderRequestSlotState,
    event: &JournalEvent,
    turn_id: &str,
) -> Result<()> {
    if state == ProviderRequestSlotState::AwaitingTools {
        return Ok(());
    }
    Err(OxidraError::Session(format!(
        "{} at seq {} cannot run for turn {turn_id} from Provider request-slot state {state:?}",
        event.kind, event.seq
    )))
}

fn required_response_attempt_id(event: &JournalEvent) -> Result<&str> {
    response_attempt_id(event).ok_or_else(|| {
        OxidraError::Session(format!(
            "{} at seq {} has no response_attempt_id",
            event.kind, event.seq
        ))
    })
}

fn required_call_id(event: &JournalEvent) -> Result<&str> {
    event_call_id(event)
        .filter(|call_id| !call_id.trim().is_empty())
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "{} at seq {} has no call_id",
                event.kind, event.seq
            ))
        })
}

fn response_function_call_ids(event: &JournalEvent) -> Result<Vec<String>> {
    let items = event
        .data
        .get("output_items")
        .and_then(Value::as_array)
        .or_else(|| {
            event
                .data
                .get("raw_response")
                .and_then(|response| response.get("output"))
                .and_then(Value::as_array)
        })
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "response.completed at seq {} has no committed output array",
                event.seq
            ))
        })?;
    items
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .map(|item| {
            item.get("call_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)
                .filter(|call_id| !call_id.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    OxidraError::Session(format!(
                        "function call in response.completed at seq {} has no call_id",
                        event.seq
                    ))
                })
        })
        .collect()
}

#[derive(Clone, Copy)]
enum SlotCallMatch {
    Started,
    InDoubt,
    Unstarted,
    AnyPending,
}

fn slot_call_index(
    calls: &[ProviderSlotCall],
    call_indexes: &HashMap<String, usize>,
    event: &JournalEvent,
    match_kind: SlotCallMatch,
) -> Result<usize> {
    let call_id = required_call_id(event)?;
    let matches_kind = |call: &ProviderSlotCall| match match_kind {
        SlotCallMatch::Started => call.started_seq.is_some(),
        SlotCallMatch::InDoubt => call.in_doubt,
        SlotCallMatch::Unstarted => call.started_seq.is_none(),
        SlotCallMatch::AnyPending => true,
    };
    let position = call_indexes.get(call_id).copied().filter(|index| {
        let call = &calls[*index];
        // Frozen v1/v2 semantics used `started_seq` only as a preferred
        // lookup and then fell back to the unique call_id. Preserve that
        // compatibility while making both paths O(1).
        !call.terminal && matches_kind(call)
    });
    position.ok_or_else(|| {
        OxidraError::Session(format!(
            "{} at seq {} does not match pending call {call_id}",
            event.kind, event.seq
        ))
    })
}

fn response_attempt_id(event: &JournalEvent) -> Option<&str> {
    event
        .data
        .get("response_attempt_id")
        .and_then(Value::as_str)
        .filter(|attempt_id| !attempt_id.trim().is_empty())
}

fn validate_call_outputs(turn_events: &[&JournalEvent]) -> Result<CallValidation> {
    #[derive(Default)]
    struct CallOccurrence {
        call_id: Option<String>,
        started_seq: Option<u64>,
        in_doubt: bool,
        terminal: bool,
    }

    let mut calls = Vec::<CallOccurrence>::new();
    let mut uncertain = false;
    for event in turn_events {
        if event.kind == "response.completed" {
            for item in response_output_items(event) {
                if item.get("type").and_then(Value::as_str) != Some("function_call") {
                    continue;
                }
                let call_id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                uncertain |= call_id.is_none();
                calls.push(CallOccurrence {
                    call_id,
                    ..CallOccurrence::default()
                });
            }
            continue;
        }

        if event.kind == "tool.started" {
            let call_id = event_call_id(event);
            let position = call_id.and_then(|call_id| {
                calls.iter().position(|call| {
                    !call.terminal
                        && call.started_seq.is_none()
                        && call.call_id.as_deref() == Some(call_id)
                })
            });
            if let Some(position) = position {
                calls[position].started_seq = Some(event.seq);
            } else {
                uncertain = true;
            }
            continue;
        }

        if event.kind == "tool.in_doubt" {
            let call_id = event_call_id(event);
            let started_seq = event.data.get("started_seq").and_then(Value::as_u64);
            let position = started_seq
                .and_then(|started_seq| {
                    calls
                        .iter()
                        .position(|call| !call.terminal && call.started_seq == Some(started_seq))
                })
                .or_else(|| {
                    call_id.and_then(|call_id| {
                        calls.iter().rposition(|call| {
                            !call.terminal
                                && call.started_seq.is_some()
                                && call.call_id.as_deref() == Some(call_id)
                        })
                    })
                })
                .or_else(|| {
                    call_id.and_then(|call_id| {
                        calls.iter().rposition(|call| {
                            !call.terminal && call.call_id.as_deref() == Some(call_id)
                        })
                    })
                });
            if let Some(position) = position {
                calls[position].in_doubt = true;
            } else {
                uncertain = true;
            }
            continue;
        }

        if is_tool_terminal_v1(&event.kind) {
            let call_id = event_call_id(event);
            let started_seq = event.data.get("started_seq").and_then(Value::as_u64);
            let position = started_seq
                .and_then(|started_seq| {
                    calls
                        .iter()
                        .position(|call| !call.terminal && call.started_seq == Some(started_seq))
                })
                .or_else(|| {
                    if event.kind == "tool.in_doubt_resolved" {
                        call_id.and_then(|call_id| {
                            calls.iter().rposition(|call| {
                                !call.terminal
                                    && call.in_doubt
                                    && call.call_id.as_deref() == Some(call_id)
                            })
                        })
                    } else if event.kind.starts_with("tool.skipped_due_to_") {
                        call_id.and_then(|call_id| {
                            calls.iter().position(|call| {
                                !call.terminal
                                    && call.started_seq.is_none()
                                    && call.call_id.as_deref() == Some(call_id)
                            })
                        })
                    } else {
                        call_id
                            .and_then(|call_id| {
                                calls.iter().rposition(|call| {
                                    !call.terminal
                                        && !call.in_doubt
                                        && call.started_seq.is_some()
                                        && call.call_id.as_deref() == Some(call_id)
                                })
                            })
                            .or_else(|| {
                                call_id.and_then(|call_id| {
                                    calls.iter().position(|call| {
                                        !call.terminal
                                            && call.started_seq.is_none()
                                            && call.call_id.as_deref() == Some(call_id)
                                    })
                                })
                            })
                    }
                });
            if let Some(position) = position {
                calls[position].terminal = true;
                calls[position].in_doubt = false;
            } else {
                uncertain = true;
            }
        }
    }
    let pending_count = calls.iter().filter(|call| !call.terminal).count();
    Ok(CallValidation {
        pending_count,
        unresolved_in_doubt: calls.iter().any(|call| !call.terminal && call.in_doubt),
        uncertain,
    })
}

fn response_has_function_call(event: &JournalEvent) -> bool {
    response_output_items(event)
        .iter()
        .any(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
}

fn response_output_items(event: &JournalEvent) -> Vec<&Value> {
    event
        .data
        .get("output_items")
        .and_then(Value::as_array)
        .or_else(|| {
            event
                .data
                .get("raw_response")
                .and_then(|response| response.get("output"))
                .and_then(Value::as_array)
        })
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn required_u64(event: &JournalEvent, field: &str) -> Result<u64> {
    event
        .data
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            OxidraError::Session(format!(
                "{} at seq {} has no valid {field}",
                event.kind, event.seq
            ))
        })
}

fn event_call_id(event: &JournalEvent) -> Option<&str> {
    event
        .data
        .get("call_id")
        .or_else(|| event.data.get("id"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::{
        COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND, validate_compaction_boundary_chain,
    };
    use serde_json::json;

    fn fixture_events() -> Vec<JournalEvent> {
        include_str!("../tests/fixtures/retry_recovery_v2.jsonl")
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("retry_recovery_v2 fixture line {}: {error}", index + 1)
                })
            })
            .collect()
    }

    fn checkpointed_budget_limit_fixture() -> Vec<JournalEvent> {
        include_str!("../tests/fixtures/checkpointed_budget_limit_55e5b0c.jsonl")
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!(
                        "checkpointed_budget_limit_55e5b0c fixture line {}: {error}",
                        index + 1
                    )
                })
            })
            .collect()
    }

    fn provider_budget_retry_event() -> JournalEvent {
        global_event(
            11,
            COMPACTION_BOUNDARY_BUDGET_RETRY_STARTED_KIND,
            json!({
                "retry_version":1,
                "retry_id":"budget-retry-1",
                "previous_boundary_id":"legacy-budget-boundary",
                "boundary":{
                    "version":4,
                    "boundary_id":"replacement-boundary",
                    "turn_id":"turn-2",
                    "user_message_seq":5
                },
                "checkpoint_id":"checkpoint-v2",
                "limit_seq":10,
                "previous_limit":1,
                "current_limit":2,
                "budget_disabled":false,
                "consumed_provider_call_intents":1
            }),
        )
    }

    fn event(seq: u64, turn_id: &str, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: chrono::DateTime::from_timestamp(0, 0).expect("valid test timestamp"),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: Some(turn_id.to_owned()),
            data,
        }
    }

    fn global_event(seq: u64, kind: &str, data: Value) -> JournalEvent {
        JournalEvent {
            schema: 1,
            seq,
            ts: chrono::DateTime::from_timestamp(0, 0).expect("valid test timestamp"),
            kind: kind.to_owned(),
            session_id: "session".to_owned(),
            turn_id: None,
            data,
        }
    }

    #[test]
    fn current_reducer_clones_deep_public_fixture_iteratively() {
        let mut data = Value::Null;
        for _ in 0..20_000 {
            data = Value::Array(vec![data]);
        }
        let event = global_event(1, "custom.deep_fixture", data);

        assert!(
            segment_turns(std::slice::from_ref(&event))
                .expect("projection-neutral public fixtures must not overflow recursive Clone")
                .is_empty()
        );
    }

    fn mcp_v4_activation(seq: u64) -> JournalEvent {
        global_event(
            seq,
            "mcp.registry.activated",
            json!({
                "bindings":[],
                "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "call_chain_validator_version":4,
                "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000001",
                "coordinator_version":4,
                "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "registry_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "registry_epoch_id":"0190f5e6-7b00-7abc-8000-000000000002",
                "registry_version":1,
                "schema_profile_version":1,
                "stdio_kernel_version":1,
                "surface_claim_version":1,
            }),
        )
    }

    fn user(seq: u64, turn_id: &str, tagged: bool) -> JournalEvent {
        let mut data = json!({
            "item": {"role": "user", "content": turn_id},
        });
        if tagged {
            data["turn_boundary_version"] = json!(TURN_BOUNDARY_VERSION);
        }
        event(seq, turn_id, "user.message", data)
    }

    fn user_with_boundary_version(seq: u64, turn_id: &str, version: u64) -> JournalEvent {
        event(
            seq,
            turn_id,
            "user.message",
            json!({
                "item": {"role": "user", "content": turn_id},
                "turn_boundary_version": version,
            }),
        )
    }

    fn response(seq: u64, turn_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "response.completed",
            json!({"output_items": [{"type": "message", "id": format!("m-{seq}")}]}),
        )
    }

    fn inline_response(seq: u64, turn_id: &str, covers_from_seq: u64) -> JournalEvent {
        let mut response = response(seq, turn_id);
        response.data["turn_completion"] = json!({
            "turn_boundary_version": TURN_BOUNDARY_VERSION,
            "covers_from_seq": covers_from_seq,
            "final_response_seq": seq,
            "covers_through_seq": seq,
        });
        response
    }

    fn call(seq: u64, turn_id: &str, call_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "response.completed",
            json!({
                "output_items": [{
                    "type": "function_call",
                    "call_id": call_id,
                    "name": "read",
                    "arguments": "{}",
                }],
            }),
        )
    }

    fn tool_output(seq: u64, turn_id: &str, call_id: &str) -> JournalEvent {
        event(
            seq,
            turn_id,
            "tool.completed",
            json!({"call_id": call_id, "output": "ok"}),
        )
    }

    #[test]
    fn frozen_turn_validator_v2_remains_literal_after_v3_upgrade() {
        let events = fixture_events();

        let historical = segment_turns_for_version(2, &events)
            .expect_err("the frozen v2 reducer must retain the old cancellation semantics");
        assert!(
            historical
                .to_string()
                .contains("does not describe a complete turn"),
            "unexpected v2 error: {historical}"
        );

        let current =
            segment_turns_for_version(3, &events).expect("v3 supersedes old cancellation");
        assert_eq!(current.len(), 1);
        assert_eq!(
            current[0].state,
            TurnState::Complete(CompletionEvidence::InlineResponse)
        );
        assert_eq!(current[0].covers_through_seq, 8);
        assert!(
            complete_prefix_candidates_for_version(3, &events)
                .expect("v3 prefix reduction")
                .iter()
                .any(|candidate| candidate.covers_through_seq == 8)
        );

        let mut v3_tagged = events.clone();
        v3_tagged[0].data["turn_boundary_version"] = json!(3);
        v3_tagged[7].data["turn_completion"]["turn_boundary_version"] = json!(3);
        let unsupported = segment_turns_for_version(2, &v3_tagged)
            .expect_err("the frozen v2 normalizer must not learn the v3 boundary tag");
        assert!(
            unsupported
                .to_string()
                .contains("unsupported turn boundary version 3"),
            "unexpected v2 tag error: {unsupported}"
        );

        let dynamic = segment_turns(&events)
            .expect("the public reader uses v8 structure with the owning v2 recovery language");
        assert_eq!(
            dynamic[0].state,
            TurnState::Complete(CompletionEvidence::InlineResponse)
        );
    }

    #[test]
    fn current_turn_validator_keeps_registered_mcp_v1_activation_readable() {
        let mut events = vec![global_event(
            1,
            "mcp.registry.activated",
            json!({
                "coordinator_version":1,
                "call_chain_validator_version":1,
                "coordinator_id":"0190f5e6-7b00-7abc-8000-000000000001",
                "registry_epoch_id":"0190f5e6-7b00-7abc-8000-000000000002",
                "registry_version":1,
                "stdio_kernel_version":1,
                "schema_profile_version":1,
                "config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "execution_plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "registry_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "provider_names":[],
            }),
        )];
        events.push(user(2, "turn-current", true));
        events.push(inline_response(3, "turn-current", 2));

        let turns = segment_turns_v8(&events)
            .expect("current turn validator must dispatch the durable v1 MCP reducer");
        assert_eq!(turns.len(), 1);
        assert!(matches!(turns[0].state, TurnState::Complete(_)));
    }

    #[test]
    fn public_turn_reader_does_not_bypass_the_current_mcp_chain_validator() {
        let events = vec![
            global_event(1, "mcp.registry.activated", json!({})),
            user_with_boundary_version(2, "turn-current", 8),
        ];

        let error = segment_turns(&events)
            .expect_err("public segmentation must reject a malformed MCP activation")
            .to_string();
        assert!(error.contains("mcp.registry.activated"), "{error}");
    }

    #[test]
    fn turn_v8_and_provider_slot_v5_are_the_first_v4_compatible_reducers() {
        assert_eq!(TURN_BOUNDARY_VALIDATOR_VERSION, 8);
        assert_eq!(PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION, 5);
        let events = vec![mcp_v4_activation(1), user(2, "turn-v4", false)];

        let turn_error = segment_turns_for_version(7, &events)
            .expect_err("turn v7 must retain its call-chain v2 ceiling")
            .to_string();
        assert!(
            turn_error.contains("compatibility ceiling 2"),
            "{turn_error}"
        );
        segment_turns_for_version(8, &events).expect("turn v8 accepts call-chain v4");

        let slot_error = provider_request_slot_state_for_version(4, &events, "turn-v4")
            .expect_err("slot v4 must retain its call-chain v2 ceiling")
            .to_string();
        assert!(
            slot_error.contains("compatibility ceiling 2"),
            "{slot_error}"
        );
        assert_eq!(
            provider_request_slot_state_for_version(5, &events, "turn-v4")
                .expect("slot v5 accepts call-chain v4"),
            ProviderRequestSlotState::Ready
        );
    }

    #[test]
    fn turn_v7_does_not_learn_the_v8_boundary_tag() {
        let events = vec![user(1, "turn-v8", true), inline_response(2, "turn-v8", 1)];
        segment_turns_for_version(8, &events).expect("turn v8 accepts its current tag");
        let error = segment_turns_for_version(7, &events)
            .expect_err("frozen turn v7 must reject a v8 boundary tag")
            .to_string();
        assert!(
            error.contains("unsupported turn boundary version 8"),
            "{error}"
        );
    }

    #[test]
    fn frozen_recovery_v2_keeps_the_pre_v3_ordering_contract() {
        let mut events = vec![
            event(1, "limited", "context.limit_reached", json!({})),
            user(2, "limited", true),
            event(
                3,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":2,"reason":"historical v2 fixture"}),
            ),
        ];

        assert!(
            validate_turn_recovery_v2(&events).is_ok(),
            "v2 accepted this ordering before the v3 repair"
        );
        assert!(
            validate_turn_recovery_v3(&events).is_err(),
            "v3 must enforce user.message < context.limit_reached < control event"
        );

        // The recovery validator and the published turn reducer are separate
        // frozen languages. v2 recovery accepted this ordering, but the v2
        // structural reducer still rejected the pre-user row as outside the
        // turn. The dynamic reader may provide compatibility without changing
        // the literal `segment_turns_for_version(2)` contract used by durable
        // compaction artifacts.
        events[1].data["turn_boundary_version"] = json!(2);
        let error = segment_turns_for_version(2, &events)
            .expect_err("frozen turn reducer v2 must remain literal")
            .to_string();
        assert!(error.contains("appears outside turn limited"), "{error}");
    }

    #[test]
    fn partitioned_recovery_rejects_orphan_and_unowned_controls() {
        let user = user_with_boundary_version(1, "known", 8);
        for (turn_id, kind, data) in [
            (
                Some("ghost"),
                "turn.abandoned",
                json!({"user_message_seq": 99, "reason": "forged"}),
            ),
            (
                Some("ghost"),
                "turn.retry_started",
                json!({
                    "retry_version": 1,
                    "retry_id": "orphan-retry",
                    "user_message_seq": 99,
                    "context_limit_seq": 98,
                }),
            ),
            (
                None,
                "turn.abandoned",
                json!({"user_message_seq": 1, "reason": "unowned"}),
            ),
        ] {
            let mut control = event(2, turn_id.unwrap_or("placeholder"), kind, data);
            control.turn_id = turn_id.map(str::to_owned);
            let error = segment_turns(&[user.clone(), control])
                .expect_err("recovery control must have one durable owning user turn")
                .to_string();
            assert!(
                error.contains("references unknown turn") || error.contains("has no turn_id"),
                "{kind}: {error}"
            );
        }
    }

    #[test]
    fn dynamic_recovery_preserves_mixed_languages_and_requires_exact_owners() {
        let mixed = vec![
            user_with_boundary_version(1, "legacy-v2", 2),
            event(
                2,
                "legacy-v2",
                "context.limit_reached",
                json!({"source":"provider"}),
            ),
            event(
                3,
                "legacy-v2",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"legacy-retry",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
            user_with_boundary_version(4, "current-v8", 8),
        ];
        let recovery = validate_turn_recovery_dynamic(&mixed)
            .expect("each turn selects its owning user.message recovery language");
        assert_eq!(recovery.retries.len(), 1);
        assert_eq!(recovery.retries[0].retry_id, "legacy-retry");

        for (kind, data) in [
            ("context.limit_reached", json!({})),
            (
                "response.failed",
                json!({"response_attempt_id":"orphan-attempt"}),
            ),
            ("turn.completed", json!({})),
        ] {
            let orphan = event(1, "ghost", kind, data);
            let error = validate_turn_recovery_dynamic(&[orphan])
                .expect_err("a full-history recovery consumer must not drop orphan protocol rows")
                .to_string();
            assert!(
                error.contains("references unknown turn ghost"),
                "{kind}: {error}"
            );
        }

        let mut unowned_user = user_with_boundary_version(1, "missing", 8);
        unowned_user.turn_id = None;
        let error = validate_turn_recovery_dynamic(&[unowned_user])
            .expect_err("user.message must select one owned recovery language")
            .to_string();
        assert!(
            error.contains("user.message at seq 1 has no turn_id"),
            "{error}"
        );
    }

    fn marker(
        seq: u64,
        turn_id: &str,
        covers_from_seq: u64,
        final_response_seq: u64,
    ) -> JournalEvent {
        event(
            seq,
            turn_id,
            "turn.completed",
            json!({
                "turn_boundary_version": TURN_BOUNDARY_VERSION,
                "covers_from_seq": covers_from_seq,
                "final_response_seq": final_response_seq,
                "covers_through_seq": seq,
            }),
        )
    }

    fn remap_sequence_fields(value: &mut Value, mapping: &HashMap<u64, u64>) {
        match value {
            Value::Array(values) => {
                for value in values {
                    remap_sequence_fields(value, mapping);
                }
            }
            Value::Object(fields) => {
                for (name, value) in fields {
                    if matches!(
                        name.as_str(),
                        "started_seq"
                            | "covers_from_seq"
                            | "final_response_seq"
                            | "covers_through_seq"
                    ) {
                        if let Some(remapped) = value.as_u64().and_then(|seq| mapping.get(&seq)) {
                            *value = json!(remapped);
                        }
                    } else {
                        remap_sequence_fields(value, mapping);
                    }
                }
            }
            _ => {}
        }
    }

    fn renumber(events: &mut [JournalEvent], first_seq: u64) {
        let mapping = events
            .iter()
            .enumerate()
            .map(|(index, event)| (event.seq, first_seq + index as u64))
            .collect::<HashMap<_, _>>();
        for event in events {
            remap_sequence_fields(&mut event.data, &mapping);
            event.seq = mapping[&event.seq];
        }
    }

    fn semantic_turns(events: &[JournalEvent]) -> Vec<(String, TurnState, bool)> {
        segment_turns(events)
            .expect("valid turns")
            .into_iter()
            .map(|turn| (turn.turn_id, turn.state, turn.cut_safe))
            .collect()
    }

    fn semantic_cutoffs(events: &[JournalEvent]) -> Vec<(usize, Option<String>, String)> {
        complete_prefix_candidates(events)
            .expect("valid prefixes")
            .into_iter()
            .map(|candidate| {
                let boundary = events
                    .iter()
                    .find(|event| event.seq == candidate.covers_through_seq)
                    .expect("cutoff references a journal event");
                (
                    candidate.turn_count,
                    boundary.turn_id.clone(),
                    boundary.kind.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn explicit_turn_without_tools_is_complete() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
        ];

        let turns = segment_turns(&events).expect("valid turn");
        assert_eq!(turns.len(), 1);
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
        assert_eq!(turns[0].covers_from_seq, 1);
        assert_eq!(turns[0].covers_through_seq, 3);
        assert!(turns[0].cut_safe);
        assert_eq!(
            complete_prefix_candidates(&events).expect("valid prefix"),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 3,
            }]
        );
    }

    #[test]
    fn historical_turn_boundary_v1_is_addressable_by_literal_version() {
        let events = vec![
            event(
                1,
                "t1",
                "user.message",
                json!({
                    "turn_boundary_version": 1,
                    "item": {"role": "user", "content": "question"},
                }),
            ),
            response(2, "t1"),
            event(
                3,
                "t1",
                "turn.completed",
                json!({
                    "turn_boundary_version": 1,
                    "covers_from_seq": 1,
                    "final_response_seq": 2,
                    "covers_through_seq": 3,
                }),
            ),
            event(
                4,
                "t2",
                "user.message",
                json!({
                    "turn_boundary_version": 1,
                    "item": {"role": "user", "content": "pending question"},
                }),
            ),
            call(5, "t2", "pending-call"),
            event(6, "t2", "tool.started", json!({"call_id": "pending-call"})),
            event(
                7,
                "t2",
                "tool.in_doubt",
                json!({"call_id": "pending-call", "started_seq": 6}),
            ),
        ];

        let turns = segment_turns_for_version(1, &events).expect("v1 remains registered");
        assert_eq!(
            turns.iter().map(|turn| turn.state).collect::<Vec<_>>(),
            vec![
                TurnState::Complete(CompletionEvidence::ExplicitMarker),
                TurnState::InDoubt,
            ]
        );
        assert_eq!(
            complete_prefix_candidates_for_version(1, &events).expect("v1 remains registered"),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 3,
            }]
        );
        assert!(complete_prefix_candidates_for_version(999, &events).is_err());
    }

    #[test]
    fn inline_response_recovers_the_marker_crash_window() {
        let events = vec![user(1, "t1", true), inline_response(2, "t1", 1)];

        let turns = segment_turns(&events).expect("valid inline boundary");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::InlineResponse)
        );
        assert!(turns[0].cut_safe);
        assert_eq!(turns[0].covers_through_seq, 2);
    }

    #[test]
    fn untagged_journal_defaults_to_legacy_completion_evidence() {
        let events = vec![
            user(1, "legacy", false),
            response(3, "legacy"),
            user(4, "next", false),
        ];

        let turns = segment_turns(&events).expect("valid legacy boundary");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::LegacyNextUser)
        );
        assert_eq!(turns[0].completion_seq, Some(3));
    }

    #[test]
    fn compaction_reducer_claim_does_not_upgrade_the_underlying_turn_language() {
        let events = vec![
            user(1, "v4", false),
            response(2, "v4"),
            global_event(
                3,
                "compaction.started",
                json!({
                    "covers_through_seq": 2,
                    "turn_boundary_validator_version": 4,
                }),
            ),
            user(4, "next", false),
        ];

        let turns = segment_turns(&events).expect("compaction metadata is projection-neutral");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::LegacyNextUser)
        );
        assert_eq!(turns[0].completion_seq, Some(2));
    }

    #[test]
    fn mixed_legacy_and_tagged_turns_keep_each_completion_language() {
        let events = vec![
            user(1, "legacy", false),
            response(2, "legacy"),
            user_with_boundary_version(3, "v4", 4),
            response(4, "v4"),
            user_with_boundary_version(5, "tail", 4),
        ];

        let turns = segment_turns(&events).expect("mixed historical boundary versions");
        assert_eq!(turns[0].completion_seq, Some(2));
        assert_eq!(turns[1].state, TurnState::Incomplete);
        assert_eq!(turns[1].completion_seq, None);
    }

    #[test]
    fn later_v8_turn_does_not_retroactively_apply_v3_recovery_binding() {
        // Frozen v2 accepted a provider-labelled context limit without the
        // later response-attempt binding.  Keep that old turn readable when a
        // subsequent v8 turn raises the current structural reducer.
        let events = vec![
            user_with_boundary_version(1, "legacy-v2", 2),
            event(
                2,
                "legacy-v2",
                "context.limit_reached",
                json!({"source": "provider"}),
            ),
            user_with_boundary_version(3, "current-v8", 8),
            inline_response(4, "current-v8", 3),
        ];

        let turns = segment_turns(&events).expect("mixed frozen recovery languages remain valid");
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].state, TurnState::LimitReached);
        assert!(matches!(turns[1].state, TurnState::Complete(_)));
    }

    #[test]
    fn v2_pre_user_context_limit_remains_representable_in_a_later_v8_journal() {
        let events = vec![
            event(1, "legacy-v2", "context.limit_reached", json!({})),
            user_with_boundary_version(2, "legacy-v2", 2),
            event(
                3,
                "legacy-v2",
                "turn.abandoned",
                json!({"user_message_seq": 2, "reason": "historical v2 fixture"}),
            ),
            user_with_boundary_version(4, "current-v8", 8),
            inline_response(5, "current-v8", 4),
        ];

        let turns = segment_turns(&events).expect("legacy v2 prefix must not be rejected by v8");
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].state, TurnState::LimitReached);
        assert!(matches!(turns[1].state, TurnState::Complete(_)));
        assert_eq!(
            segment_turns_for_version(8, &events)
                .expect("the persisted v8 reducer owns the same mixed-language semantics"),
            turns
        );
    }

    #[test]
    fn later_terminal_tag_does_not_upgrade_the_owning_users_recovery_language() {
        let events = vec![
            user_with_boundary_version(1, "legacy-v2", 2),
            event(
                2,
                "legacy-v2",
                "response.failed",
                json!({"turn_boundary_version": 8}),
            ),
            event(
                3,
                "legacy-v2",
                "context.limit_reached",
                json!({"source": "provider"}),
            ),
        ];

        let turns = segment_turns(&events)
            .expect("a later terminal cannot retroactively select recovery v3");
        assert_eq!(turns[0].state, TurnState::Failed);
    }

    #[test]
    fn unknown_boundary_claim_fails_closed_before_reducer_dispatch() {
        let events = vec![user_with_boundary_version(1, "future", 9)];

        let error = segment_turns(&events).expect_err("future boundary must fail closed");
        assert!(
            error
                .to_string()
                .contains("unsupported turn boundary version 9")
        );
    }

    #[test]
    fn frozen_turn_reducers_keep_legacy_completion_seq_until_v4() {
        let events = vec![
            user(1, "legacy", false),
            response(2, "legacy"),
            user(3, "next", false),
        ];
        for version in 1..=3 {
            assert_eq!(
                segment_turns_for_version(version, &events)
                    .expect("historical reducer remains readable")[0]
                    .completion_seq,
                Some(2),
                "turn validator v{version} must retain its published evidence seq"
            );
        }
        assert_eq!(
            segment_turns_for_version(4, &events).expect("v4 reducer uses the evidence event")[0]
                .completion_seq,
            Some(3)
        );
    }

    #[test]
    fn request_slot_readiness_is_independent_from_open_tail_state() {
        let user_only = vec![user(1, "ready", true)];
        assert_eq!(
            segment_turns(&user_only).expect("user-only turn")[0].state,
            TurnState::OpenTail
        );
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &user_only,
                "ready"
            )
            .expect("user-only slot"),
            ProviderRequestSlotState::Ready
        );

        let in_flight = vec![
            user(1, "in-flight", true),
            event(
                2,
                "in-flight",
                "response.started",
                json!({"response_attempt_id":"attempt-1"}),
            ),
        ];
        let turns = segment_turns(&in_flight).expect("valid in-flight response");
        assert_eq!(turns[0].state, TurnState::OpenTail);
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &in_flight,
                "in-flight"
            )
            .expect("in-flight slot"),
            ProviderRequestSlotState::ResponseInFlight
        );
    }

    #[test]
    fn provider_slot_does_not_reinterpret_an_unrelated_v2_retry_with_v3() {
        let events = vec![
            user_with_boundary_version(1, "legacy-v2", 2),
            event(
                2,
                "legacy-v2",
                "context.limit_reached",
                json!({"source":"provider"}),
            ),
            event(
                3,
                "legacy-v2",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"legacy-retry",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
            mcp_v4_activation(4),
            user_with_boundary_version(5, "modern-mcp", 8),
        ];

        validate_turn_recovery_v2(&events[..3]).expect("the legacy retry is valid recovery v2");
        assert!(
            validate_turn_recovery_v3(&events).is_err(),
            "a whole-journal recovery-v3 pass would retroactively reject the v2 prefix"
        );
        assert_eq!(
            provider_request_slot_state_for_version(5, &events, "modern-mcp")
                .expect("the modern MCP slot only validates its owning turn with recovery v3"),
            ProviderRequestSlotState::Ready
        );
        validate_provider_request_slots_v2(&events, &["modern-mcp".to_owned()])
            .expect("the batch slot validator must apply the same target-turn scope");
    }

    #[test]
    fn request_slot_requires_resolved_tools_and_response_attempts() {
        let mut events = vec![
            user(1, "tools", true),
            event(
                2,
                "tools",
                "response.started",
                json!({"response_attempt_id":"attempt-1"}),
            ),
            event(
                3,
                "tools",
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-1",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-1",
                        "name":"read",
                        "arguments":"{}",
                    }],
                }),
            ),
        ];
        let pending = segment_turns(&events).expect("valid pending tool call");
        assert_eq!(pending[0].state, TurnState::OpenTail);
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                "tools"
            )
            .expect("pending tool slot"),
            ProviderRequestSlotState::AwaitingTools
        );

        events.push(event(
            4,
            "tools",
            "tool.started",
            json!({"call_id":"call-1"}),
        ));
        events.push(event(
            5,
            "tools",
            "tool.completed",
            json!({"call_id":"call-1","started_seq":4,"output":"ok"}),
        ));
        let resolved = segment_turns(&events).expect("valid resolved tool call");
        assert_eq!(resolved[0].state, TurnState::OpenTail);
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                "tools"
            )
            .expect("resolved tool slot"),
            ProviderRequestSlotState::Ready
        );
    }

    #[test]
    fn request_slot_rejects_concurrent_response_attempts() {
        let events = vec![
            user(1, "concurrent", true),
            event(
                2,
                "concurrent",
                "response.started",
                json!({"response_attempt_id":"attempt-a"}),
            ),
            event(
                3,
                "concurrent",
                "response.started",
                json!({"response_attempt_id":"attempt-b"}),
            ),
        ];
        assert!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                "concurrent"
            )
            .is_err()
        );
    }

    #[test]
    fn request_slot_rejects_next_response_before_tool_resolution() {
        let events = vec![
            user(1, "causal", true),
            event(
                2,
                "causal",
                "response.started",
                json!({"response_attempt_id":"attempt-a"}),
            ),
            event(
                3,
                "causal",
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-a",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-1",
                        "name":"read",
                        "arguments":"{}"
                    }]
                }),
            ),
            event(
                4,
                "causal",
                "response.started",
                json!({"response_attempt_id":"attempt-b"}),
            ),
        ];
        let error = provider_request_slot_state_for_version(
            PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
            &events,
            "causal",
        )
        .expect_err("tool result must precede the next Provider request")
        .to_string();
        assert!(error.contains("cannot acquire"));
    }

    #[test]
    fn request_slot_retry_reacquires_a_terminal_attempt() {
        let events = vec![
            user(1, "limited", true),
            event(
                2,
                "limited",
                "response.started",
                json!({"response_attempt_id":"attempt-old"}),
            ),
            event(
                3,
                "limited",
                "response.failed",
                json!({"response_attempt_id":"attempt-old"}),
            ),
            event(4, "limited", "context.limit_reached", json!({})),
            event(
                5,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":4,
                }),
            ),
        ];

        let turns = segment_turns(&events).expect("valid retry epoch");
        assert_eq!(turns[0].state, TurnState::OpenTail);
        assert_eq!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &events,
                "limited"
            )
            .expect("retry slot"),
            ProviderRequestSlotState::Ready
        );

        let unresolved_before_retry = vec![
            user(1, "limited-tools", true),
            event(
                2,
                "limited-tools",
                "response.started",
                json!({"response_attempt_id":"attempt-tools"}),
            ),
            event(
                3,
                "limited-tools",
                "response.completed",
                json!({
                    "response_attempt_id":"attempt-tools",
                    "output_items":[{
                        "type":"function_call",
                        "call_id":"call-pending",
                        "name":"read",
                        "arguments":"{}",
                    }],
                }),
            ),
            event(
                4,
                "limited-tools",
                "response.started",
                json!({"response_attempt_id":"attempt-limit"}),
            ),
            event(
                5,
                "limited-tools",
                "response.failed",
                json!({"response_attempt_id":"attempt-limit"}),
            ),
            event(6, "limited-tools", "context.limit_reached", json!({})),
            event(
                7,
                "limited-tools",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-tools",
                    "user_message_seq":1,
                    "context_limit_seq":6,
                }),
            ),
        ];
        let turns = segment_turns(&unresolved_before_retry).expect("turn segmentation is separate");
        assert_eq!(turns[0].state, TurnState::OpenTail);
        assert!(
            provider_request_slot_state_for_version(
                PROVIDER_REQUEST_SLOT_VALIDATOR_VERSION,
                &unresolved_before_retry,
                "limited-tools"
            )
            .is_err()
        );
    }

    #[test]
    fn provider_budget_retry_is_versioned_and_does_not_rewrite_frozen_reducers() {
        let legacy = checkpointed_budget_limit_fixture();
        assert_eq!(
            provider_request_slot_state_for_version(1, &legacy, "turn-2")
                .expect("frozen slot v1 reads the legacy terminal"),
            ProviderRequestSlotState::Terminal
        );
        assert_eq!(
            segment_turns_for_version(4, &legacy)
                .expect("frozen turn v4 reads the legacy terminal")
                .last()
                .expect("fixture has the limited turn")
                .state,
            TurnState::LimitReached
        );

        let mut migrated = legacy.clone();
        migrated.push(provider_budget_retry_event());

        assert_eq!(
            validate_provider_budget_retries_v1(&migrated)
                .expect("valid budget retry")
                .len(),
            1
        );
        assert_eq!(
            provider_request_slot_state_for_version(1, &migrated, "turn-2")
                .expect("slot v1 remains frozen"),
            ProviderRequestSlotState::Terminal
        );
        assert_eq!(
            provider_request_slot_state_for_version(2, &migrated, "turn-2")
                .expect("slot v2 consumes the explicit migration"),
            ProviderRequestSlotState::Ready
        );
        assert_eq!(
            segment_turns_for_version(4, &migrated)
                .expect("turn v4 remains frozen")
                .last()
                .expect("fixture has the limited turn")
                .state,
            TurnState::LimitReached
        );
        assert_eq!(
            segment_turns_for_version(5, &migrated)
                .expect("turn v5 consumes the explicit migration")
                .last()
                .expect("fixture has the resumed turn")
                .state,
            TurnState::OpenTail
        );
        validate_compaction_boundary_chain(&migrated)
            .expect("boundary, turn, and slot reducers consume the same canonical migration");
    }

    #[test]
    fn provider_budget_retry_rejects_forged_or_duplicate_grants() {
        let base = checkpointed_budget_limit_fixture();
        let valid = provider_budget_retry_event();

        for (field, value) in [
            ("retry_id", json!("")),
            ("limit_seq", json!(999)),
            ("current_limit", json!(1)),
            ("consumed_provider_call_intents", json!(0)),
        ] {
            let mut events = base.clone();
            let mut forged = valid.clone();
            forged.data[field] = value;
            events.push(forged);
            assert!(
                validate_provider_budget_retries_v1(&events).is_err(),
                "forged {field} must fail closed"
            );
        }

        for (field, value) in [
            ("previous_boundary_id", json!("missing-boundary")),
            ("checkpoint_id", json!("missing-checkpoint")),
        ] {
            let mut events = base.clone();
            let mut forged = valid.clone();
            forged.data[field] = value;
            events.push(forged);
            assert!(
                segment_turns_for_version(5, &events).is_err(),
                "turn v5 must reject forged {field} lineage"
            );
            assert!(
                provider_request_slot_state_for_version(2, &events, "turn-2").is_err(),
                "slot v2 must reject forged {field} lineage"
            );
            assert!(
                validate_compaction_boundary_chain(&events).is_err(),
                "boundary v4 must reject forged {field} lineage"
            );
        }

        let mut wrong_user = base.clone();
        let mut forged = valid.clone();
        forged.data["boundary"]["user_message_seq"] = json!(2);
        wrong_user.push(forged);
        assert!(segment_turns_for_version(5, &wrong_user).is_err());
        assert!(provider_request_slot_state_for_version(2, &wrong_user, "turn-2").is_err());
        assert!(validate_compaction_boundary_chain(&wrong_user).is_err());

        let mut duplicate = base;
        duplicate.push(valid.clone());
        let mut second = valid;
        second.seq = 4;
        second.data["retry_id"] = json!("budget-retry-2");
        second.data["boundary"]["boundary_id"] = json!("replacement-boundary-2");
        duplicate.push(second);
        assert!(
            validate_provider_budget_retries_v1(&duplicate).is_err(),
            "one legacy terminal cannot mint two budget grants"
        );
    }

    #[test]
    fn explicit_turn_with_multiple_tool_rounds_is_complete() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            tool_output(3, "t1", "c1"),
            call(4, "t1", "c2"),
            tool_output(5, "t1", "c2"),
            response(6, "t1"),
            marker(7, "t1", 1, 6),
        ];

        assert_eq!(
            segment_turns(&events).expect("valid turn")[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
    }

    #[test]
    fn cancelled_and_aborted_turns_are_not_complete() {
        let events = vec![
            user(1, "cancelled", true),
            event(2, "cancelled", "turn.cancelled", json!({})),
            user(3, "aborted", true),
            event(4, "aborted", "response.aborted", json!({})),
            user(5, "tail", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::Cancelled);
        assert_eq!(turns[1].state, TurnState::Aborted);
        assert_eq!(turns[2].state, TurnState::OpenTail);
        assert!(turns[0].cut_safe);
        assert!(turns[1].cut_safe);
        assert!(!turns[2].cut_safe);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn terminal_failure_does_not_block_a_later_complete_cutoff() {
        let events = vec![
            user(1, "failed", true),
            event(2, "failed", "response.failed", json!({})),
            user(3, "complete", true),
            response(4, "complete"),
            marker(5, "complete", 3, 4),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::Failed);
        assert!(turns[0].cut_safe);
        assert_eq!(
            complete_prefix_candidates(&events).unwrap(),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 5,
            }]
        );
    }

    #[test]
    fn unresolved_in_doubt_call_blocks_completion() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            event(3, "t1", "tool.in_doubt", json!({"call_id": "c1"})),
            user(4, "t2", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::InDoubt);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn legacy_middle_turn_closes_but_legacy_tail_stays_open() {
        let events = vec![
            user(1, "legacy-1", false),
            response(2, "legacy-1"),
            user(3, "legacy-2", false),
            response(4, "legacy-2"),
        ];

        let turns = segment_turns(&events).expect("valid legacy turns");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::LegacyNextUser)
        );
        assert_eq!(turns[1].state, TurnState::OpenTail);
        assert_eq!(
            complete_prefix_candidates(&events).expect("valid prefix"),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 2,
            }]
        );
    }

    #[test]
    fn tagged_turn_without_marker_never_uses_legacy_completion() {
        let events = vec![
            user(1, "tagged", true),
            response(2, "tagged"),
            user(3, "next", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::Incomplete);
        assert!(turns[0].cut_safe);
        assert!(
            complete_prefix_candidates(&events)
                .expect("valid prefixes")
                .is_empty()
        );
    }

    #[test]
    fn resolved_in_doubt_turn_does_not_block_a_later_complete_cutoff() {
        let events = vec![
            user(1, "uncertain", true),
            call(2, "uncertain", "c1"),
            event(3, "uncertain", "tool.started", json!({"call_id": "c1"})),
            event(
                4,
                "uncertain",
                "tool.in_doubt",
                json!({"call_id": "c1", "started_seq": 3}),
            ),
            event(
                5,
                "uncertain",
                "tool.in_doubt_resolved",
                json!({"call_id": "c1", "started_seq": 3}),
            ),
            user(6, "complete", true),
            response(7, "complete"),
            marker(8, "complete", 6, 7),
        ];

        let turns = segment_turns(&events).unwrap();
        assert_eq!(turns[0].state, TurnState::Incomplete);
        assert!(turns[0].cut_safe);
        assert_eq!(
            complete_prefix_candidates(&events).unwrap(),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 8,
            }]
        );
    }

    #[test]
    fn rejects_marker_with_inconsistent_coverage() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 99, 2),
        ];

        let error = segment_turns(&events).expect_err("coverage must be rejected");
        assert!(error.to_string().contains("inconsistent coverage"));
    }

    #[test]
    fn rejects_marker_that_points_to_a_tool_call_response() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            tool_output(3, "t1", "c1"),
            marker(4, "t1", 1, 2),
        ];

        let error = segment_turns(&events).expect_err("non-final response must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not reference a final response")
        );
    }

    #[test]
    fn rejects_marker_that_points_to_a_missing_response() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 99),
        ];

        let error = segment_turns(&events).expect_err("missing response must be rejected");
        assert!(error.to_string().contains("references missing response"));
    }

    #[test]
    fn rejects_marker_that_points_before_the_last_response() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            response(3, "t1"),
            marker(4, "t1", 1, 2),
        ];

        let error = segment_turns(&events).expect_err("earlier response must be rejected");
        assert!(error.to_string().contains("last response terminal event"));
    }

    #[test]
    fn context_limit_is_a_terminal_non_complete_state() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "context.limit_reached", json!({})),
            user(3, "next", true),
        ];

        let turns = segment_turns(&events).expect("valid turns");
        assert_eq!(turns[0].state, TurnState::LimitReached);
        assert!(complete_prefix_candidates(&events).unwrap().is_empty());
    }

    #[test]
    fn validates_abandon_only_for_the_matching_pending_context_turn() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "context.limit_reached", json!({})),
            event(
                3,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"retry"}),
            ),
        ];
        let validated = validate_turn_recovery(&events).expect("valid abandon");
        let abandon = validated.abandons.get("limited").expect("validated turn");
        assert_eq!(abandon.user_message_seq, 1);
        assert_eq!(abandon.limit_seq, 2);
        assert_eq!(abandon.abandon_seq, 3);
    }

    #[test]
    fn forged_abandon_events_fail_closed() {
        let completed = vec![
            user(1, "done", true),
            inline_response(2, "done", 1),
            event(
                3,
                "done",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"forged"}),
            ),
        ];
        assert!(validate_turn_recovery(&completed).is_err());

        let no_limit = vec![
            user(1, "done", true),
            event(
                2,
                "done",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"forged"}),
            ),
        ];
        assert!(validate_turn_recovery(&no_limit).is_err());

        let out_of_order = vec![
            user(1, "limited", true),
            event(
                2,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"forged"}),
            ),
            event(3, "limited", "context.limit_reached", json!({})),
        ];
        assert!(validate_turn_recovery(&out_of_order).is_err());

        let limit_before_user = vec![
            event(1, "limited", "context.limit_reached", json!({})),
            user(2, "limited", true),
            event(
                3,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":2,"reason":"forged"}),
            ),
        ];
        assert!(validate_turn_recovery(&limit_before_user).is_err());
    }

    #[test]
    fn duplicate_abandon_events_fail_closed() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "context.limit_reached", json!({})),
            event(
                3,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"retry"}),
            ),
            event(
                4,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"retry again"}),
            ),
        ];
        assert!(validate_turn_recovery(&events).is_err());
    }

    #[test]
    fn retry_intent_is_versioned_and_references_the_latest_limit() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "response.failed", json!({})),
            event(3, "limited", "context.limit_reached", json!({})),
            event(
                4,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":3,
                }),
            ),
        ];
        let recovery = validate_turn_recovery(&events).expect("valid retry intent");
        assert_eq!(recovery.retries.len(), 1);
        assert_eq!(recovery.retries[0].retry_id, "retry-1");
        assert_eq!(recovery.retries[0].limit_seq, 3);
    }

    #[test]
    fn retry_without_a_new_limit_or_after_completion_fails_closed() {
        let duplicate = vec![
            user(1, "limited", true),
            event(2, "limited", "context.limit_reached", json!({})),
            event(
                3,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
            event(
                4,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-2",
                    "user_message_seq":1,
                    "context_limit_seq":2,
                }),
            ),
        ];
        assert!(validate_turn_recovery(&duplicate).is_err());

        let completed = vec![
            user(1, "done", true),
            inline_response(2, "done", 1),
            marker(3, "done", 1, 2),
            event(4, "done", "context.limit_reached", json!({})),
            event(
                5,
                "done",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-forged",
                    "user_message_seq":1,
                    "context_limit_seq":4,
                }),
            ),
        ];
        assert!(validate_turn_recovery(&completed).is_err());

        let limit_before_user = vec![
            event(1, "limited", "context.limit_reached", json!({})),
            user(2, "limited", true),
            event(
                3,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-forged-order",
                    "user_message_seq":2,
                    "context_limit_seq":1,
                }),
            ),
        ];
        assert!(validate_turn_recovery(&limit_before_user).is_err());
    }

    #[test]
    fn provider_context_limit_must_bind_to_the_failed_response_attempt() {
        let mismatched = vec![
            user(1, "limited", true),
            event(
                2,
                "limited",
                "response.failed",
                json!({"response_attempt_id":"attempt-a"}),
            ),
            event(
                3,
                "limited",
                "context.limit_reached",
                json!({
                    "source":"provider",
                    "response_attempt_id":"attempt-b",
                }),
            ),
            event(
                4,
                "limited",
                "turn.abandoned",
                json!({"user_message_seq":1,"reason":"forged"}),
            ),
        ];
        assert!(validate_turn_recovery(&mismatched).is_err());

        let mut matched = mismatched;
        matched[2].data["response_attempt_id"] = json!("attempt-a");
        assert!(validate_turn_recovery(&matched).is_ok());
    }

    #[test]
    fn boundary_v3_allows_a_successful_response_after_a_persisted_retry() {
        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "response.failed", json!({})),
            event(3, "limited", "context.limit_reached", json!({})),
            event(
                4,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-1",
                    "user_message_seq":1,
                    "context_limit_seq":3,
                }),
            ),
            inline_response(5, "limited", 1),
            marker(6, "limited", 1, 5),
        ];
        let turns = segment_turns(&events).expect("retry should restore completion semantics");
        assert_eq!(
            turns[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
        assert_eq!(complete_prefix_candidates(&events).unwrap().len(), 1);
    }

    #[test]
    fn boundary_v3_supersedes_every_earlier_retry_attempt_terminal() {
        for terminal_kind in [
            "turn.cancelled",
            "agent.stalled",
            "agent.limit_reached",
            "response.aborted",
        ] {
            let events = vec![
                user(1, "limited", true),
                event(2, "limited", "response.failed", json!({})),
                event(3, "limited", "context.limit_reached", json!({})),
                event(
                    4,
                    "limited",
                    "turn.retry_started",
                    json!({
                        "retry_version":1,
                        "retry_id":format!("retry-1-{terminal_kind}"),
                        "user_message_seq":1,
                        "context_limit_seq":3,
                    }),
                ),
                event(5, "limited", terminal_kind, json!({})),
                event(
                    6,
                    "limited",
                    "turn.retry_started",
                    json!({
                        "retry_version":1,
                        "retry_id":format!("retry-2-{terminal_kind}"),
                        "user_message_seq":1,
                        "context_limit_seq":3,
                    }),
                ),
                inline_response(7, "limited", 1),
                marker(8, "limited", 1, 7),
            ];
            let turns =
                segment_turns(&events).unwrap_or_else(|error| panic!("{terminal_kind}: {error}"));
            assert!(
                matches!(turns[0].state, TurnState::Complete(_)),
                "{terminal_kind}: {:?}",
                turns[0].state
            );
        }

        let events = vec![
            user(1, "limited", true),
            event(2, "limited", "response.failed", json!({})),
            event(3, "limited", "context.limit_reached", json!({})),
            event(
                4,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-before-limit",
                    "user_message_seq":1,
                    "context_limit_seq":3,
                }),
            ),
            event(5, "limited", "context.limit_reached", json!({})),
            event(
                6,
                "limited",
                "turn.retry_started",
                json!({
                    "retry_version":1,
                    "retry_id":"retry-after-limit",
                    "user_message_seq":1,
                    "context_limit_seq":5,
                }),
            ),
            inline_response(7, "limited", 1),
            marker(8, "limited", 1, 7),
        ];
        assert!(matches!(
            segment_turns(&events).unwrap()[0].state,
            TurnState::Complete(_)
        ));
    }

    #[test]
    fn rejects_function_call_output_crossing_turn_boundary() {
        let events = vec![
            user(1, "t1", false),
            call(2, "t1", "c1"),
            user(3, "t2", false),
            tool_output(4, "t2", "c1"),
        ];

        let turns = segment_turns(&events).expect("malformed pairing is conservatively retained");
        assert!(!turns[0].cut_safe);
        assert!(complete_prefix_candidates(&events).unwrap().is_empty());
    }

    #[test]
    fn duplicate_call_ids_follow_started_call_order() {
        let events = vec![
            user(1, "t1", true),
            event(
                2,
                "t1",
                "response.completed",
                json!({"output_items": [
                    {"type": "function_call", "call_id": "same"},
                    {"type": "function_call", "call_id": "same"},
                ]}),
            ),
            event(3, "t1", "tool.started", json!({"call_id": "same"})),
            tool_output(4, "t1", "same"),
            event(5, "t1", "tool.started", json!({"call_id": "same"})),
            tool_output(6, "t1", "same"),
            response(7, "t1"),
            marker(8, "t1", 1, 7),
        ];

        assert_eq!(
            segment_turns(&events).unwrap()[0].state,
            TurnState::Complete(CompletionEvidence::ExplicitMarker)
        );
    }

    #[test]
    fn segmentation_and_prefix_candidates_are_deterministic() {
        let events = vec![
            user(1, "t1", true),
            response(2, "t1"),
            marker(3, "t1", 1, 2),
            user(4, "t2", true),
            response(5, "t2"),
            marker(6, "t2", 4, 5),
        ];

        let first_turns = segment_turns(&events).expect("valid turns");
        let first_prefixes = complete_prefix_candidates(&events).expect("valid prefixes");
        for _ in 0..3 {
            assert_eq!(segment_turns(&events).expect("valid turns"), first_turns);
            assert_eq!(
                complete_prefix_candidates(&events).expect("valid prefixes"),
                first_prefixes
            );
        }
    }

    #[test]
    fn neutral_global_events_do_not_change_turn_boundaries() {
        let mut global = event(
            2,
            "unused",
            "context.instructions",
            json!({"instructions": "snapshot"}),
        );
        global.turn_id = None;
        let events = vec![
            user(1, "t1", true),
            global,
            response(3, "t1"),
            marker(4, "t1", 1, 3),
        ];

        assert_eq!(
            complete_prefix_candidates(&events).unwrap(),
            vec![CompletePrefix {
                turn_count: 1,
                covers_through_seq: 4,
            }]
        );
    }

    #[test]
    fn inserting_projection_neutral_global_events_preserves_state_and_cutoff_relation() {
        let base = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            tool_output(3, "t1", "c1"),
            response(4, "t1"),
            marker(5, "t1", 1, 4),
            user(6, "t2", true),
            response(7, "t2"),
            marker(8, "t2", 6, 7),
        ];
        let expected_turns = semantic_turns(&base);
        let expected_cutoffs = semantic_cutoffs(&base);

        for kind in [
            "context.instructions",
            "context.configured",
            "context.tools",
            "render.compact",
            "session.metadata",
        ] {
            for insertion_index in 0..=base.len() {
                let mut enriched = base.clone();
                let mut global = event(u64::MAX, "unused", kind, json!({}));
                global.turn_id = None;
                enriched.insert(insertion_index, global);
                renumber(&mut enriched, 1);

                assert_eq!(
                    semantic_turns(&enriched),
                    expected_turns,
                    "turn state changed after inserting {kind} at index {insertion_index}"
                );
                assert_eq!(
                    semantic_cutoffs(&enriched),
                    expected_cutoffs,
                    "cutoff relation changed after inserting {kind} at index {insertion_index}"
                );
            }
        }
    }

    #[test]
    fn legal_sequence_translation_preserves_state_and_translates_cutoffs() {
        let events = vec![
            user(1, "t1", true),
            call(2, "t1", "c1"),
            event(3, "t1", "tool.started", json!({"call_id": "c1"})),
            tool_output(4, "t1", "c1"),
            response(5, "t1"),
            marker(6, "t1", 1, 5),
            user(7, "t2", true),
            inline_response(8, "t2", 7),
        ];
        let original_turns = segment_turns(&events).expect("valid original turns");
        let original_cutoffs = complete_prefix_candidates(&events).expect("valid cutoffs");
        let offset = 10_000;
        let mut translated = events.clone();
        renumber(&mut translated, offset + 1);

        let translated_turns = segment_turns(&translated).expect("valid translated turns");
        assert_eq!(translated_turns.len(), original_turns.len());
        for (original, translated) in original_turns.iter().zip(&translated_turns) {
            assert_eq!(translated.turn_id, original.turn_id);
            assert_eq!(translated.start_index, original.start_index);
            assert_eq!(translated.end_index_exclusive, original.end_index_exclusive);
            assert_eq!(translated.state, original.state);
            assert_eq!(translated.cut_safe, original.cut_safe);
            assert_eq!(
                translated.covers_from_seq,
                original.covers_from_seq + offset
            );
            assert_eq!(
                translated.covers_through_seq,
                original.covers_through_seq + offset
            );
        }

        let translated_cutoffs =
            complete_prefix_candidates(&translated).expect("valid translated cutoffs");
        assert_eq!(translated_cutoffs.len(), original_cutoffs.len());
        for (original, translated) in original_cutoffs.iter().zip(&translated_cutoffs) {
            assert_eq!(translated.turn_count, original.turn_count);
            assert_eq!(
                translated.covers_through_seq,
                original.covers_through_seq + offset
            );
        }
    }

    #[test]
    fn pending_call_variants_never_produce_a_prefix_candidate() {
        let cases = vec![
            (
                "declared",
                vec![
                    user(1, "pending", false),
                    call(2, "pending", "c1"),
                    response(3, "pending"),
                    user(4, "later", true),
                    response(5, "later"),
                    marker(6, "later", 4, 5),
                ],
            ),
            (
                "started",
                vec![
                    user(1, "pending", false),
                    call(2, "pending", "c1"),
                    event(3, "pending", "tool.started", json!({"call_id": "c1"})),
                    response(4, "pending"),
                    user(5, "later", true),
                    response(6, "later"),
                    marker(7, "later", 5, 6),
                ],
            ),
            (
                "one_of_two_resolved",
                vec![
                    user(1, "pending", false),
                    event(
                        2,
                        "pending",
                        "response.completed",
                        json!({"output_items": [
                            {"type": "function_call", "call_id": "c1"},
                            {"type": "function_call", "call_id": "c2"},
                        ]}),
                    ),
                    tool_output(3, "pending", "c1"),
                    response(4, "pending"),
                    user(5, "later", true),
                    response(6, "later"),
                    marker(7, "later", 5, 6),
                ],
            ),
            (
                "in_doubt",
                vec![
                    user(1, "pending", false),
                    call(2, "pending", "c1"),
                    event(3, "pending", "tool.started", json!({"call_id": "c1"})),
                    event(
                        4,
                        "pending",
                        "tool.in_doubt",
                        json!({"call_id": "c1", "started_seq": 3}),
                    ),
                    response(5, "pending"),
                    user(6, "later", true),
                    response(7, "later"),
                    marker(8, "later", 6, 7),
                ],
            ),
        ];

        for (name, events) in cases {
            let turns = segment_turns(&events).expect("valid turns");
            assert!(!turns[0].cut_safe, "{name} pending call became cut-safe");
            assert!(
                matches!(turns[1].state, TurnState::Complete(_)),
                "{name} fixture must contain a later complete turn"
            );
            assert!(
                complete_prefix_candidates(&events)
                    .expect("valid prefix reduction")
                    .is_empty(),
                "{name} pending call produced a prefix candidate"
            );
        }
    }

    #[test]
    fn provider_projectable_event_cannot_reference_an_unknown_turn() {
        let events = vec![response(1, "ghost")];

        let error = segment_turns(&events).expect_err("orphan response must be rejected");
        assert!(error.to_string().contains("references unknown turn ghost"));
    }
}
