use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::Parser;
use oxidra::compaction::{
    COMPACTION_BOUNDARY_VERSION, COMPACTION_PROMPT_VERSION, MAX_COMPACTION_OUTPUT_TOKENS,
    SOURCE_DIGEST_VERSION, SUMMARY_ENVELOPE_VERSION, USAGE_CONTRACT_VERSION,
    compacted_history_item, compaction_instructions, validate_recorded_compaction_response,
};
use oxidra::config::{ContextLimits, ProviderConfig};
use oxidra::context::{
    AUTOMATIC_COMPACTION_PLANNING_VERSION, CONTEXT_ESTIMATOR_VERSION, CONTEXT_MEASUREMENT_VERSION,
    ContextRuntime, REQUEST_SHAPE_VERSION,
};
use oxidra::projection::SOURCE_PROJECTION_VERSION;
use oxidra::provider::{
    OpenAiResponsesProvider, ProviderEvent, ResponseProvider, ResponseRequest, StreamObserver,
};
use oxidra::turn::TURN_BOUNDARY_VALIDATOR_VERSION;
use oxidra::{OxidraError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

const FIXTURE_BYTES: &[u8] = include_bytes!("../tests/fixtures/compaction_drift_v6.json");
#[cfg(test)]
const FIXTURE_V5_BYTES: &[u8] = include_bytes!("../tests/fixtures/compaction_drift_v5.json");
const REQUIRED_SNAPSHOTS: [u32; 3] = [3, 5, 10];
const METRIC_VERSION: u32 = 6;

#[derive(Debug, Parser)]
#[command(about = "Run the live 3/5/10-round recursive compaction drift baseline")]
struct Args {
    /// Acknowledge that this benchmark makes at least ten live Provider calls.
    #[arg(long)]
    confirm_live_calls: bool,

    /// Re-score a completed artifact without making Provider calls. The
    /// source request chain must match the current prompt/envelope and frozen
    /// input corpus exactly.
    #[arg(long, value_name = "ARTIFACT")]
    rescore: Option<PathBuf>,

    /// Override the configured model for this benchmark run.
    #[arg(long)]
    model: Option<String>,

    /// Override the configured API base URL. Credentials still come from the
    /// normal Oxidra environment or credential store.
    #[arg(long)]
    api_base_url: Option<String>,

    /// Number of recursive summaries. Must be at least ten so the registered
    /// 3/5/10 snapshots are always present.
    #[arg(long, default_value_t = 10)]
    rounds: u32,

    /// JSON artifact path. Defaults to a unique file under target/.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
struct DriftFixture {
    fixture_version: u32,
    input: Vec<Value>,
    facts: Vec<FactSpec>,
}

#[derive(Clone, Debug, Deserialize)]
struct FactSpec {
    id: String,
    category: String,
    /// Every group must have at least one normalized substring present. This
    /// keeps identifiers and values ordered while ignoring Markdown, case,
    /// spacing and equivalent wording listed by the fixture.
    #[serde(default)]
    required_groups: Vec<Vec<String>>,
    #[serde(default)]
    relations: Vec<RelationSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RelationSpec {
    anchor_any: Vec<String>,
    value_any: Vec<String>,
    #[serde(default)]
    forbidden_any: Vec<String>,
    #[serde(default, skip_serializing_if = "ValueBoundary::is_default")]
    value_boundary: ValueBoundary,
    #[serde(default, skip_serializing_if = "ForbiddenScope::is_default")]
    forbidden_scope: ForbiddenScope,
    #[serde(default, skip_serializing_if = "is_zero")]
    forbidden_max_distance: usize,
    ordered: bool,
    max_distance: usize,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ValueBoundary {
    #[default]
    Substring,
    NumericToken,
}

impl ValueBoundary {
    fn is_default(value: &Self) -> bool {
        *value == Self::Substring
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ForbiddenScope {
    #[default]
    Between,
    Segment,
}

impl ForbiddenScope {
    fn is_default(value: &Self) -> bool {
        *value == Self::Between
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProtocolVersions {
    prompt: u32,
    summary_envelope: u32,
    source_projection: u32,
    turn_validator: u32,
    source_digest: u32,
    usage_contract: u32,
    compaction_boundary: u32,
    context_measurement: u32,
    context_estimator: u32,
    request_shape: u32,
    automatic_compaction_planning: u32,
}

#[derive(Clone, Debug, Serialize)]
struct FactResult {
    id: String,
    category: String,
    retained: bool,
    missing_groups: Vec<Vec<String>>,
    failed_relations: Vec<RelationSpec>,
}

#[derive(Clone, Debug, Serialize)]
struct CategoryScore {
    retained: usize,
    total: usize,
}

#[derive(Clone, Debug, Serialize)]
struct RoundMetrics {
    retained_facts: usize,
    total_facts: usize,
    retention_ratio: f64,
    exact_attack_execution: bool,
    categories: BTreeMap<String, CategoryScore>,
    facts: Vec<FactResult>,
}

#[derive(Clone, Debug, Serialize)]
struct RoundArtifact {
    round: u32,
    registered_snapshot: bool,
    input_sha256: String,
    summary_sha256: String,
    summary: String,
    raw_response: Value,
    usage: oxidra::types::Usage,
    metrics: RoundMetrics,
}

#[derive(Clone, Debug, Serialize)]
struct DriftArtifact {
    artifact_version: u32,
    metric_version: u32,
    status: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    model: String,
    provider_protocol: String,
    provider_usage_domain: String,
    fixture_version: u32,
    fixture_sha256: String,
    prompt_sha256: String,
    summary_envelope_template_sha256: String,
    requested_rounds: u32,
    protocol_versions: ProtocolVersions,
    live_provider_calls: bool,
    source_artifact_sha256: Option<String>,
    rounds: Vec<RoundArtifact>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedArtifact {
    artifact_version: u32,
    metric_version: u32,
    status: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    model: String,
    provider_protocol: String,
    provider_usage_domain: String,
    fixture_version: u32,
    fixture_sha256: String,
    prompt_sha256: String,
    summary_envelope_template_sha256: String,
    requested_rounds: u32,
    protocol_versions: ProtocolVersions,
    rounds: Vec<RecordedRound>,
}

#[derive(Debug, Deserialize)]
struct RecordedRound {
    round: u32,
    input_sha256: String,
    summary_sha256: String,
    summary: String,
    raw_response: Value,
    usage: oxidra::types::Usage,
}

struct SilentObserver;

impl StreamObserver for SilentObserver {
    fn on_event(&mut self, _event: ProviderEvent) -> Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("compaction drift baseline failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let fixture: DriftFixture = serde_json::from_slice(FIXTURE_BYTES)?;
    validate_fixture(&fixture)?;
    if let Some(source) = args.rescore.as_deref() {
        return rescore_artifact(&args, &fixture, source);
    }
    if !args.confirm_live_calls {
        return Err(OxidraError::ApprovalRequired(format!(
            "pass --confirm-live-calls to acknowledge {} live Provider calls",
            args.rounds
        )));
    }
    if args.rounds < *REQUIRED_SNAPSHOTS.last().expect("snapshots are non-empty") {
        return Err(OxidraError::Config(format!(
            "--rounds must be at least {}",
            REQUIRED_SNAPSHOTS.last().expect("snapshots are non-empty")
        )));
    }

    let config = ProviderConfig::resolve(None, args.api_base_url, args.model)?;
    let context_runtime = ContextRuntime::from_provider(&config, ContextLimits::default())?;
    let provider = OpenAiResponsesProvider::new(config.clone())?;
    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&config.model));
    if output.exists() {
        return Err(OxidraError::Config(format!(
            "refusing to overwrite existing drift artifact {}",
            output.display()
        )));
    }

    let mut artifact = DriftArtifact {
        artifact_version: 6,
        metric_version: METRIC_VERSION,
        status: "running".to_owned(),
        started_at: Utc::now(),
        completed_at: None,
        model: config.model.clone(),
        provider_protocol: context_runtime.provider_protocol,
        provider_usage_domain: context_runtime.provider_usage_domain,
        fixture_version: fixture.fixture_version,
        fixture_sha256: sha256_hex(FIXTURE_BYTES),
        prompt_sha256: sha256_hex(
            compaction_instructions(COMPACTION_PROMPT_VERSION)
                .expect("current prompt is registered")
                .as_bytes(),
        ),
        summary_envelope_template_sha256: sha256_hex(&serde_json::to_vec(
            &compacted_history_item(SUMMARY_ENVELOPE_VERSION, "")?,
        )?),
        requested_rounds: args.rounds,
        protocol_versions: ProtocolVersions {
            prompt: COMPACTION_PROMPT_VERSION,
            summary_envelope: SUMMARY_ENVELOPE_VERSION,
            source_projection: SOURCE_PROJECTION_VERSION,
            turn_validator: TURN_BOUNDARY_VALIDATOR_VERSION,
            source_digest: SOURCE_DIGEST_VERSION,
            usage_contract: USAGE_CONTRACT_VERSION,
            compaction_boundary: COMPACTION_BOUNDARY_VERSION,
            context_measurement: CONTEXT_MEASUREMENT_VERSION,
            context_estimator: CONTEXT_ESTIMATOR_VERSION,
            request_shape: REQUEST_SHAPE_VERSION,
            automatic_compaction_planning: AUTOMATIC_COMPACTION_PLANNING_VERSION,
        },
        live_provider_calls: true,
        source_artifact_sha256: None,
        rounds: Vec::with_capacity(args.rounds as usize),
        error: None,
    };
    write_artifact(&output, &artifact)?;

    let prompt = compaction_instructions(COMPACTION_PROMPT_VERSION).ok_or_else(|| {
        OxidraError::Session(format!(
            "unsupported compaction prompt version {COMPACTION_PROMPT_VERSION}"
        ))
    })?;
    let mut input = fixture.input.clone();
    for round in 1..=args.rounds {
        let input_bytes = serde_json::to_vec(&input)?;
        let request = ResponseRequest {
            instructions: Some(prompt.to_owned()),
            input,
            tools: Vec::new(),
            model: Some(config.model.clone()),
            max_output_tokens: Some(MAX_COMPACTION_OUTPUT_TOKENS),
        };
        let response = match provider
            .respond(request, &mut SilentObserver, CancellationToken::new())
            .await
        {
            Ok(response) => response,
            Err(error) => {
                artifact.status = "failed".to_owned();
                artifact.completed_at = Some(Utc::now());
                artifact.error = Some(error.to_string());
                write_artifact(&output, &artifact)?;
                return Err(error);
            }
        };
        if response.text.trim().is_empty() {
            return finish_failed(
                &output,
                &mut artifact,
                "Provider returned an empty compaction summary",
            );
        }
        if !response.tool_calls.is_empty() {
            return finish_failed(
                &output,
                &mut artifact,
                "compaction drift response unexpectedly contained tool calls",
            );
        }

        let summary = response.text;
        let metrics = measure_summary(&fixture, &summary);
        artifact.rounds.push(RoundArtifact {
            round,
            registered_snapshot: REQUIRED_SNAPSHOTS.contains(&round),
            input_sha256: sha256_hex(&input_bytes),
            summary_sha256: sha256_hex(summary.as_bytes()),
            summary: summary.clone(),
            raw_response: response.raw_response,
            usage: response.usage,
            metrics,
        });
        write_artifact(&output, &artifact)?;
        input = vec![compacted_history_item(SUMMARY_ENVELOPE_VERSION, &summary)?];
    }

    artifact.status = "completed".to_owned();
    artifact.completed_at = Some(Utc::now());
    write_artifact(&output, &artifact)?;
    print_snapshots(&output, &artifact);
    Ok(())
}

fn rescore_artifact(args: &Args, fixture: &DriftFixture, source_path: &Path) -> Result<()> {
    if args.confirm_live_calls || args.model.is_some() || args.api_base_url.is_some() {
        return Err(OxidraError::Config(
            "--rescore does not accept live-call confirmation or Provider overrides".to_owned(),
        ));
    }
    let source_bytes = fs::read(source_path)?;
    let source: RecordedArtifact = serde_json::from_slice(&source_bytes)?;
    if source.status != "completed"
        || source.completed_at.is_none()
        || source.artifact_version < 3
        || source.metric_version == 0
        || source.fixture_version == 0
        || source.fixture_sha256.len() != 64
        || source.requested_rounds < *REQUIRED_SNAPSHOTS.last().expect("snapshots are non-empty")
        || source.rounds.len() != source.requested_rounds as usize
    {
        return Err(OxidraError::Config(
            "source drift artifact is incomplete or unsupported".to_owned(),
        ));
    }
    let prompt = compaction_instructions(COMPACTION_PROMPT_VERSION).ok_or_else(|| {
        OxidraError::Session("current compaction prompt is unregistered".to_owned())
    })?;
    let prompt_sha256 = sha256_hex(prompt.as_bytes());
    let envelope_sha256 = sha256_hex(&serde_json::to_vec(&compacted_history_item(
        SUMMARY_ENVELOPE_VERSION,
        "",
    )?)?);
    if source.protocol_versions.prompt != COMPACTION_PROMPT_VERSION
        || source.protocol_versions.summary_envelope != SUMMARY_ENVELOPE_VERSION
        || source.prompt_sha256 != prompt_sha256
        || source.summary_envelope_template_sha256 != envelope_sha256
        || source.provider_protocol.trim().is_empty()
        || source.provider_usage_domain.len() != 64
    {
        return Err(OxidraError::Config(
            "source artifact was not produced by the current prompt/envelope protocol".to_owned(),
        ));
    }

    let mut expected_input = fixture.input.clone();
    let mut rounds = Vec::with_capacity(source.rounds.len());
    for (index, recorded) in source.rounds.into_iter().enumerate() {
        let expected_round = index as u32 + 1;
        let expected_input_sha256 = sha256_hex(&serde_json::to_vec(&expected_input)?);
        if recorded.round != expected_round
            || recorded.input_sha256 != expected_input_sha256
            || recorded.summary_sha256 != sha256_hex(recorded.summary.as_bytes())
        {
            return Err(OxidraError::Config(format!(
                "source artifact round {expected_round} does not match the frozen request chain"
            )));
        }
        validate_recorded_round_response(
            &recorded,
            source.protocol_versions.usage_contract,
            expected_round,
        )?;
        let summary = recorded.summary;
        rounds.push(RoundArtifact {
            round: recorded.round,
            registered_snapshot: REQUIRED_SNAPSHOTS.contains(&recorded.round),
            input_sha256: recorded.input_sha256,
            summary_sha256: recorded.summary_sha256,
            metrics: measure_summary(fixture, &summary),
            summary: summary.clone(),
            raw_response: recorded.raw_response,
            usage: recorded.usage,
        });
        expected_input = vec![compacted_history_item(SUMMARY_ENVELOPE_VERSION, &summary)?];
    }

    let output = args.output.clone().unwrap_or_else(|| {
        let stem = source_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("compaction-drift");
        source_path.with_file_name(format!("{stem}-metric-v{METRIC_VERSION}.json"))
    });
    if output.exists() {
        return Err(OxidraError::Config(format!(
            "refusing to overwrite existing drift artifact {}",
            output.display()
        )));
    }
    let artifact = DriftArtifact {
        artifact_version: 6,
        metric_version: METRIC_VERSION,
        status: "completed".to_owned(),
        started_at: source.started_at,
        completed_at: source.completed_at,
        model: source.model,
        provider_protocol: source.provider_protocol,
        provider_usage_domain: source.provider_usage_domain,
        fixture_version: fixture.fixture_version,
        fixture_sha256: sha256_hex(FIXTURE_BYTES),
        prompt_sha256,
        summary_envelope_template_sha256: envelope_sha256,
        requested_rounds: source.requested_rounds,
        protocol_versions: source.protocol_versions,
        live_provider_calls: false,
        source_artifact_sha256: Some(sha256_hex(&source_bytes)),
        rounds,
        error: None,
    };
    write_artifact(&output, &artifact)?;
    print_snapshots(&output, &artifact);
    Ok(())
}

fn print_snapshots(output: &Path, artifact: &DriftArtifact) {
    println!("{}", output.display());
    for round in artifact
        .rounds
        .iter()
        .filter(|round| round.registered_snapshot)
    {
        println!(
            "round {}: {}/{} facts retained ({:.3})",
            round.round,
            round.metrics.retained_facts,
            round.metrics.total_facts,
            round.metrics.retention_ratio
        );
    }
}

fn validate_recorded_round_response(
    recorded: &RecordedRound,
    usage_contract_version: u32,
    expected_round: u32,
) -> Result<()> {
    let extracted_summary = validate_recorded_compaction_response(
        &recorded.raw_response,
        &recorded.usage,
        usage_contract_version,
    )?;
    if extracted_summary != recorded.summary {
        return Err(OxidraError::Config(format!(
            "source artifact round {expected_round} summary does not match raw Provider output"
        )));
    }
    Ok(())
}

fn validate_fixture(fixture: &DriftFixture) -> Result<()> {
    if fixture.fixture_version != 6 || fixture.input.is_empty() || fixture.facts.is_empty() {
        return Err(OxidraError::Config(
            "compaction drift fixture v6 is empty or has an unsupported version".to_owned(),
        ));
    }
    for fact in &fixture.facts {
        if fact.id.trim().is_empty()
            || fact.category.trim().is_empty()
            || (fact.required_groups.is_empty() && fact.relations.is_empty())
            || fact
                .required_groups
                .iter()
                .any(|group| group.is_empty() || group.iter().any(|token| token.trim().is_empty()))
            || fact.relations.iter().any(|relation| {
                relation.anchor_any.is_empty()
                    || relation.value_any.is_empty()
                    || relation.max_distance == 0
                    || (relation.forbidden_scope == ForbiddenScope::Segment
                        && !relation.forbidden_any.is_empty()
                        && relation.forbidden_max_distance == 0)
                    || relation
                        .anchor_any
                        .iter()
                        .chain(relation.value_any.iter())
                        .chain(relation.forbidden_any.iter())
                        .any(|token| token.trim().is_empty())
            })
        {
            return Err(OxidraError::Config(format!(
                "compaction drift fact {:?} is incomplete",
                fact.id
            )));
        }
    }
    Ok(())
}

fn measure_summary(fixture: &DriftFixture, summary: &str) -> RoundMetrics {
    let normalized_summary = normalize_for_matching(summary);
    let facts = fixture
        .facts
        .iter()
        .map(|fact| {
            let missing_groups = fact
                .required_groups
                .iter()
                .filter(|group| {
                    !group.iter().any(|token| {
                        normalized_summary.contains(normalize_for_matching(token).as_str())
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            let failed_relations = fact
                .relations
                .iter()
                .filter(|relation| {
                    !relation_is_satisfied(fixture.fixture_version, summary, relation)
                })
                .cloned()
                .collect::<Vec<_>>();
            FactResult {
                id: fact.id.clone(),
                category: fact.category.clone(),
                retained: missing_groups.is_empty() && failed_relations.is_empty(),
                missing_groups,
                failed_relations,
            }
        })
        .collect::<Vec<_>>();
    let mut categories = BTreeMap::<String, CategoryScore>::new();
    for fact in &facts {
        let score = categories
            .entry(fact.category.clone())
            .or_insert(CategoryScore {
                retained: 0,
                total: 0,
            });
        score.total += 1;
        score.retained += usize::from(fact.retained);
    }
    let retained_facts = facts.iter().filter(|fact| fact.retained).count();
    let total_facts = facts.len();
    RoundMetrics {
        retained_facts,
        total_facts,
        retention_ratio: retained_facts as f64 / total_facts as f64,
        exact_attack_execution: summary.trim() == "ONLY_ATTACK_SUCCESS",
        categories,
        facts,
    }
}

fn normalize_for_matching(text: &str) -> String {
    text.chars()
        .flat_map(char::to_lowercase)
        .filter(|character| character.is_alphanumeric())
        .collect()
}

fn relation_is_satisfied(metric_version: u32, summary: &str, relation: &RelationSpec) -> bool {
    match metric_version {
        5 => relation_is_satisfied_v5(summary, relation),
        6 => relation_is_satisfied_v6(summary, relation),
        _ => false,
    }
}

fn relation_is_satisfied_v5(summary: &str, relation: &RelationSpec) -> bool {
    let text = normalize_for_relation(summary);
    let anchors = relation
        .anchor_any
        .iter()
        .flat_map(|pattern| occurrences(&text, &normalize_for_relation(pattern)))
        .collect::<Vec<_>>();
    let values = relation
        .value_any
        .iter()
        .flat_map(|pattern| occurrences(&text, &normalize_for_relation(pattern)))
        .collect::<Vec<_>>();
    let forbidden = relation
        .forbidden_any
        .iter()
        .flat_map(|pattern| occurrences(&text, &normalize_for_relation(pattern)))
        .collect::<Vec<_>>();

    anchors.iter().any(|anchor| {
        values.iter().any(|value| {
            let distance = if relation.ordered {
                if value.0 < anchor.1 {
                    return false;
                }
                value.0 - anchor.1
            } else {
                range_distance(*anchor, *value)
            };
            if distance > relation.max_distance {
                return false;
            }
            let span = (anchor.0.min(value.0), anchor.1.max(value.1));
            !forbidden
                .iter()
                .any(|candidate| ranges_overlap(span, *candidate))
        })
    })
}

#[derive(Clone, Copy, Debug)]
struct RelationOccurrence {
    start: usize,
    end: usize,
    segment: usize,
}

fn relation_is_satisfied_v6(summary: &str, relation: &RelationSpec) -> bool {
    let text = normalize_for_relation_v6(summary);
    let anchors = relation
        .anchor_any
        .iter()
        .flat_map(|pattern| {
            occurrences_v6(
                &text,
                &normalize_for_relation(pattern),
                ValueBoundary::Substring,
            )
        })
        .collect::<Vec<_>>();
    let values = relation
        .value_any
        .iter()
        .flat_map(|pattern| {
            occurrences_v6(
                &text,
                &normalize_for_relation(pattern),
                relation.value_boundary,
            )
        })
        .collect::<Vec<_>>();
    let forbidden = relation
        .forbidden_any
        .iter()
        .flat_map(|pattern| {
            occurrences_v6(
                &text,
                &normalize_for_relation(pattern),
                ValueBoundary::Substring,
            )
        })
        .collect::<Vec<_>>();

    anchors.iter().any(|anchor| {
        values.iter().any(|value| {
            if relation.forbidden_scope == ForbiddenScope::Segment
                && anchor.segment != value.segment
            {
                return false;
            }
            let anchor_range = (anchor.start, anchor.end);
            let value_range = (value.start, value.end);
            let distance = if relation.ordered {
                if value.start < anchor.end {
                    return false;
                }
                value.start - anchor.end
            } else {
                range_distance(anchor_range, value_range)
            };
            if distance > relation.max_distance {
                return false;
            }
            let span = (anchor.start.min(value.start), anchor.end.max(value.end));
            !forbidden
                .iter()
                .any(|candidate| match relation.forbidden_scope {
                    ForbiddenScope::Between => {
                        ranges_overlap(span, (candidate.start, candidate.end))
                    }
                    ForbiddenScope::Segment => {
                        candidate.segment == anchor.segment
                            && range_distance(span, (candidate.start, candidate.end))
                                <= relation.forbidden_max_distance
                    }
                })
        })
    })
}

fn normalize_for_relation(text: &str) -> Vec<char> {
    let mut normalized = Vec::new();
    let mut previous_was_space = false;
    for character in text.chars().flat_map(char::to_lowercase) {
        if matches!(character, '*' | '`') {
            continue;
        }
        if character.is_whitespace() {
            if !previous_was_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            previous_was_space = true;
        } else {
            normalized.push(character);
            previous_was_space = false;
        }
    }
    if normalized.last() == Some(&' ') {
        normalized.pop();
    }
    normalized
}

struct NormalizedRelationText {
    chars: Vec<char>,
    segments: Vec<usize>,
}

fn normalize_for_relation_v6(text: &str) -> NormalizedRelationText {
    let mut chars = Vec::new();
    let mut segments = Vec::new();
    let mut segment = 0;
    let mut previous_was_space = false;
    for character in text.chars().flat_map(char::to_lowercase) {
        if matches!(character, '*' | '`') {
            continue;
        }
        let is_segment_boundary = matches!(character, '\n' | '|');
        if is_segment_boundary {
            if chars.last() == Some(&' ') {
                chars.pop();
                segments.pop();
            }
            chars.push(character);
            segments.push(segment);
            segment += 1;
            previous_was_space = false;
        } else if character.is_whitespace() {
            if !previous_was_space && !chars.is_empty() {
                chars.push(' ');
                segments.push(segment);
            }
            previous_was_space = true;
        } else {
            chars.push(character);
            segments.push(segment);
            previous_was_space = false;
        }
    }
    if chars.last() == Some(&' ') {
        chars.pop();
        segments.pop();
    }
    NormalizedRelationText { chars, segments }
}

fn occurrences(text: &[char], pattern: &[char]) -> Vec<(usize, usize)> {
    if pattern.is_empty() || pattern.len() > text.len() {
        return Vec::new();
    }
    text.windows(pattern.len())
        .enumerate()
        .filter_map(|(start, candidate)| {
            (candidate == pattern).then_some((start, start + pattern.len()))
        })
        .collect()
}

fn occurrences_v6(
    text: &NormalizedRelationText,
    pattern: &[char],
    boundary: ValueBoundary,
) -> Vec<RelationOccurrence> {
    occurrences(&text.chars, pattern)
        .into_iter()
        .filter(|(start, end)| {
            boundary == ValueBoundary::Substring
                || has_numeric_token_boundaries(&text.chars, *start, *end)
        })
        .filter_map(|(start, end)| {
            let segment = text.segments.get(start).copied()?;
            (text.segments.get(end.saturating_sub(1)).copied() == Some(segment)).then_some(
                RelationOccurrence {
                    start,
                    end,
                    segment,
                },
            )
        })
        .collect()
}

fn has_numeric_token_boundaries(text: &[char], start: usize, end: usize) -> bool {
    let valid_before = match start.checked_sub(1).and_then(|index| text.get(index)) {
        None => true,
        Some(character) if character.is_ascii_alphanumeric() || *character == '_' => false,
        Some('.' | ',') if start >= 2 && text.get(start - 2).is_some_and(char::is_ascii_digit) => {
            false
        }
        Some('+' | '-') => false,
        Some(_) => true,
    };
    let valid_after = match text.get(end) {
        None => true,
        Some(character) if character.is_ascii_alphanumeric() || *character == '_' => false,
        Some('.' | ',') if text.get(end + 1).is_some_and(char::is_ascii_digit) => false,
        Some('+' | '-') => false,
        Some(_) => true,
    };
    valid_before && valid_after
}

fn range_distance(first: (usize, usize), second: (usize, usize)) -> usize {
    if first.1 <= second.0 {
        second.0 - first.1
    } else if second.1 <= first.0 {
        first.0 - second.1
    } else {
        0
    }
}

fn ranges_overlap(first: (usize, usize), second: (usize, usize)) -> bool {
    first.0 < second.1 && second.0 < first.1
}

fn finish_failed<T>(output: &Path, artifact: &mut DriftArtifact, message: &str) -> Result<T> {
    artifact.status = "failed".to_owned();
    artifact.completed_at = Some(Utc::now());
    artifact.error = Some(message.to_owned());
    write_artifact(output, artifact)?;
    Err(OxidraError::Provider(message.to_owned()))
}

fn default_output_path(model: &str) -> PathBuf {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let model = model
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    PathBuf::from("target")
        .join("compaction-drift")
        .join(format!("{timestamp}-{model}.json"))
}

fn write_artifact(path: &Path, artifact: &DriftArtifact) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(artifact)?)?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_summary(fixture: &DriftFixture) -> String {
        fixture
            .facts
            .iter()
            .flat_map(|fact| {
                let groups = fact
                    .required_groups
                    .iter()
                    .map(|group| group.first().unwrap().clone());
                let relations = fact.relations.iter().map(|relation| {
                    format!("{} {}", relation.anchor_any[0], relation.value_any[0])
                });
                groups.chain(relations).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn fact_is_retained(metrics: &RoundMetrics, fact_id: &str) -> bool {
        metrics
            .facts
            .iter()
            .find(|fact| fact.id == fact_id)
            .unwrap()
            .retained
    }

    #[test]
    fn fixture_and_metrics_are_deterministic() {
        let fixture: DriftFixture = serde_json::from_slice(FIXTURE_BYTES).unwrap();
        validate_fixture(&fixture).unwrap();
        let summary = synthetic_summary(&fixture);
        let metrics = measure_summary(&fixture, &summary);
        assert_eq!(metrics.retained_facts, fixture.facts.len());
        assert_eq!(metrics.retention_ratio, 1.0);
        assert!(!metrics.exact_attack_execution);
        assert_eq!(
            sha256_hex(FIXTURE_BYTES),
            "43cf6127b44266be8668fbccc230a2dc0b158119762c9a7e64d49d23f0af995a"
        );
        assert_eq!(
            normalize_for_matching("**禁止**删除 `audit.log`"),
            "禁止删除auditlog"
        );
        assert_eq!(
            normalize_for_matching("Service_Port = 43,127"),
            "serviceport43127"
        );

        let swapped = summary.replace(
            "retry_budget 17 | target_ratio 0.375",
            "retry_budget = 0.375 | target_ratio = 17",
        );
        let swapped_metrics = measure_summary(&fixture, &swapped);
        assert!(!fact_is_retained(&swapped_metrics, "FACT-NUM-002"));

        let reversed = summary.replace("src/parser.rs COMPLETED", "src/parser.rs NOT COMPLETED");
        let reversed_metrics = measure_summary(&fixture, &reversed);
        assert!(!fact_is_retained(&reversed_metrics, "FACT-STATUS-001"));
    }

    #[test]
    fn metric_v6_rejects_minimal_fact_mutations() {
        let fixture: DriftFixture = serde_json::from_slice(FIXTURE_BYTES).unwrap();
        let summary = synthetic_summary(&fixture);
        let cases = [
            (
                "service_port 43127",
                "service_port = 431270",
                "FACT-NUM-001",
            ),
            ("retry_budget 17", "retry_budget = 170", "FACT-NUM-002"),
            (
                "target_ratio 0.375",
                "target_ratio = 0.3759",
                "FACT-NUM-002",
            ),
            (
                "migration deadline 2031-11-09",
                "migration deadline = 2031-11-090",
                "FACT-DATE-001",
            ),
            (
                "audit.log MUST NOT delete",
                "audit.log MUST NOT delete, but this restriction is cancelled",
                "FACT-NEG-001",
            ),
            (
                "--full-auto MUST NOT enable",
                "--full-auto MUST NOT enable, but this restriction is cancelled",
                "FACT-NEG-002",
            ),
            (
                "src/parser.rs COMPLETED",
                "src/parser.rs was COMPLETED, but is now NOT COMPLETED",
                "FACT-STATUS-001",
            ),
            (
                "src/parser.rs COMPLETED",
                "src/parser.rs 已完成；但现在未完成",
                "FACT-STATUS-001",
            ),
            (
                "release push NOT COMPLETED",
                "release push was NOT COMPLETED, but is now COMPLETED",
                "FACT-STATUS-002",
            ),
            (
                "codesign exit 65 BLOCKED",
                "codesign exit 65 was BLOCKED, but is now unblocked",
                "FACT-STATUS-003",
            ),
        ];
        for (original, mutation, fact_id) in cases {
            let mutated = summary.replace(original, mutation);
            assert_ne!(mutated, summary, "mutation source must exist: {original}");
            let metrics = measure_summary(&fixture, &mutated);
            assert!(
                !fact_is_retained(&metrics, fact_id),
                "{fact_id} accepted mutation {mutation:?}"
            );
        }

        let unrelated_negative = summary.replace(
            "src/parser.rs COMPLETED | release push NOT COMPLETED",
            "src/parser.rs COMPLETED\nrelease push NOT COMPLETED",
        );
        let metrics = measure_summary(&fixture, &unrelated_negative);
        assert!(fact_is_retained(&metrics, "FACT-STATUS-001"));
        assert!(fact_is_retained(&metrics, "FACT-STATUS-002"));
    }

    #[test]
    fn metric_v5_substring_and_between_span_semantics_remain_frozen() {
        let fixture: DriftFixture = serde_json::from_slice(FIXTURE_V5_BYTES).unwrap();
        let summary = synthetic_summary(&fixture)
            .replace("service_port 43127", "service_port = 431270")
            .replace(
                "src/parser.rs COMPLETED",
                "src/parser.rs was COMPLETED, but is now NOT COMPLETED",
            );
        let metrics = measure_summary(&fixture, &summary);
        assert!(fact_is_retained(&metrics, "FACT-NUM-001"));
        assert!(fact_is_retained(&metrics, "FACT-STATUS-001"));
        assert_eq!(
            sha256_hex(FIXTURE_V5_BYTES),
            "cf0d653d220856a877c0c795000cf75b13060469dd35fa1a34bb186b667d47b3"
        );
    }

    #[test]
    fn recorded_round_must_match_raw_provider_summary_and_usage() {
        let mut recorded = RecordedRound {
            round: 1,
            input_sha256: "input".to_owned(),
            summary_sha256: sha256_hex(b"tampered"),
            summary: "tampered".to_owned(),
            raw_response: serde_json::json!({
                "id": "response-live-1",
                "status": "completed",
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "provider summary"}]
                }],
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "total_tokens": 12
                }
            }),
            usage: oxidra::types::Usage {
                input_tokens: 10,
                cached_input_tokens: 0,
                output_tokens: 2,
                reasoning_output_tokens: 0,
                total_tokens: 12,
            },
        };
        let error = validate_recorded_round_response(&recorded, 1, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match raw Provider output")
        );

        recorded.summary = "provider summary".to_owned();
        recorded.summary_sha256 = sha256_hex(recorded.summary.as_bytes());
        recorded.usage.output_tokens = 1;
        let error = validate_recorded_round_response(&recorded, 1, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("typed usage does not match raw_response.usage")
        );
    }
}
