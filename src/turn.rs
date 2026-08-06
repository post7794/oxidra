//! Deterministic turn boundaries derived from canonical journal events.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::error::{OxidraError, Result};
use crate::session::JournalEvent;

pub const TURN_BOUNDARY_VALIDATOR_VERSION: u32 = 3;
pub const TURN_BOUNDARY_VERSION: u64 = TURN_BOUNDARY_VALIDATOR_VERSION as u64;

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
pub(crate) fn validate_turn_recovery(events: &[JournalEvent]) -> Result<ValidatedTurnRecovery> {
    validate_turn_recovery_v3(events)
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
        if event.data.get("turn_completion").is_some() {
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
        if event.data.get("turn_completion").is_some() {
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
    if let Some(version) = event.data.get_mut("turn_boundary_version") {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                event.seq
            ))
        })?;
        if !matches!(value, 1 | 2) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                event.seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = event
        .data
        .get_mut("turn_completion")
        .and_then(Value::as_object_mut)
        .and_then(|completion| completion.get_mut("turn_boundary_version"))
    {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                event.seq
            ))
        })?;
        if !matches!(value, 1 | 2) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                event.seq
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
    if let Some(version) = event.data.get_mut("turn_boundary_version") {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "turn boundary version at seq {} is not an unsigned integer",
                event.seq
            ))
        })?;
        if !matches!(value, 1..=3) {
            return Err(OxidraError::Session(format!(
                "unsupported turn boundary version {value} at seq {}",
                event.seq
            )));
        }
        *version = Value::from(1);
    }
    if let Some(version) = event
        .data
        .get_mut("turn_completion")
        .and_then(Value::as_object_mut)
        .and_then(|completion| completion.get_mut("turn_boundary_version"))
    {
        let value = version.as_u64().ok_or_else(|| {
            OxidraError::Session(format!(
                "inline turn boundary version at seq {} is not an unsigned integer",
                event.seq
            ))
        })?;
        if !matches!(value, 1..=3) {
            return Err(OxidraError::Session(format!(
                "unsupported inline turn boundary version {value} at seq {}",
                event.seq
            )));
        }
        *version = Value::from(1);
    }
    Ok(())
}

fn segment_turns_v1(events: &[JournalEvent]) -> Result<Vec<TurnSpan>> {
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
        let turn_events = events[*start_index..end_index_exclusive]
            .iter()
            .filter(|event| event.turn_id.as_deref() == Some(turn_id.as_str()))
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
            .filter(|event| event.data.get("turn_completion").is_some())
            .collect::<Vec<_>>();
        if inline_completions.len() > 1 {
            return Err(OxidraError::Session(format!(
                "turn {turn_id} has more than one inline completion boundary"
            )));
        }

        let calls = validate_call_outputs(&turn_events)?;
        let has_next_user = position + 1 < starts.len();
        let inline_completion = inline_completions.first().copied();
        if let Some(response) = inline_completion {
            validate_inline_completion(user_event, response, &turn_events, &calls)?;
        }
        let (state, covers_through_seq, completion_seq) =
            if let Some(marker) = markers.first().copied() {
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
                let completion_seq = matches!(state, TurnState::Complete(_))
                    .then(|| last_response_event_seq(&turn_events))
                    .flatten();
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
    complete_prefix_candidates_for_version(TURN_BOUNDARY_VALIDATOR_VERSION, events)
}

/// Rebuild complete-prefix cutoffs using an immutable historical reducer.
pub(crate) fn complete_prefix_candidates_for_version(
    version: u32,
    events: &[JournalEvent],
) -> Result<Vec<CompletePrefix>> {
    let mut candidates = Vec::new();
    let mut complete_turns = 0;
    for turn in segment_turns_for_version(version, events)? {
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

    fn user(seq: u64, turn_id: &str, tagged: bool) -> JournalEvent {
        let mut data = json!({
            "item": {"role": "user", "content": turn_id},
        });
        if tagged {
            data["turn_boundary_version"] = json!(TURN_BOUNDARY_VERSION);
        }
        event(seq, turn_id, "user.message", data)
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
    }

    #[test]
    fn frozen_recovery_v2_keeps_the_pre_v3_ordering_contract() {
        let events = vec![
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
