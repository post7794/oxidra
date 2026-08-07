use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::Parser;
use oxidra::compaction::{
    COMPACTION_BOUNDARY_VERSION, COMPACTION_PROMPT_VERSION, MAX_COMPACTION_OUTPUT_TOKENS,
    SOURCE_DIGEST_VERSION, SUMMARY_ENVELOPE_VERSION, USAGE_CONTRACT_VERSION,
    compacted_history_item, compaction_instructions,
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

const FIXTURE_BYTES: &[u8] = include_bytes!("../tests/fixtures/compaction_drift_v4.json");
const REQUIRED_SNAPSHOTS: [u32; 3] = [3, 5, 10];
const METRIC_VERSION: u32 = 4;

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
    required_groups: Vec<Vec<String>>,
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
        artifact_version: 4,
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
        artifact_version: 4,
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

fn validate_fixture(fixture: &DriftFixture) -> Result<()> {
    if fixture.fixture_version != 4 || fixture.input.is_empty() || fixture.facts.is_empty() {
        return Err(OxidraError::Config(
            "compaction drift fixture v4 is empty or has an unsupported version".to_owned(),
        ));
    }
    for fact in &fixture.facts {
        if fact.id.trim().is_empty()
            || fact.category.trim().is_empty()
            || fact.required_groups.is_empty()
            || fact
                .required_groups
                .iter()
                .any(|group| group.is_empty() || group.iter().any(|token| token.trim().is_empty()))
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
            FactResult {
                id: fact.id.clone(),
                category: fact.category.clone(),
                retained: missing_groups.is_empty(),
                missing_groups,
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

    #[test]
    fn fixture_and_metrics_are_deterministic() {
        let fixture: DriftFixture = serde_json::from_slice(FIXTURE_BYTES).unwrap();
        validate_fixture(&fixture).unwrap();
        let summary = fixture
            .facts
            .iter()
            .flat_map(|fact| {
                fact.required_groups
                    .iter()
                    .map(|group| group.first().unwrap().clone())
            })
            .collect::<Vec<_>>()
            .join(" | ");
        let metrics = measure_summary(&fixture, &summary);
        assert_eq!(metrics.retained_facts, fixture.facts.len());
        assert_eq!(metrics.retention_ratio, 1.0);
        assert!(!metrics.exact_attack_execution);
        assert_eq!(
            sha256_hex(FIXTURE_BYTES),
            "2c6baa35dc6d37f64053204a60e70f9b7c97954e13e97c303b70e5c223378b37"
        );
        assert_eq!(
            normalize_for_matching("**禁止**删除 `audit.log`"),
            "禁止删除auditlog"
        );
        assert_eq!(
            normalize_for_matching("Service_Port = 43,127"),
            "serviceport43127"
        );
    }
}
