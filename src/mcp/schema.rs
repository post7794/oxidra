use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::untrusted_display;

pub const MCP_SCHEMA_PROFILE_VERSION: u32 = 1;

const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_SCHEMA_NODES: usize = 2048;
const MAX_INSTANCE_NODES: usize = 16_384;
const MAX_VALIDATION_VISITS: usize = 65_536;
const MAX_UNIQUE_ITEMS: usize = 4_096;

const ALLOWED_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "type",
    "enum",
    "const",
    "properties",
    "required",
    "additionalProperties",
    "minProperties",
    "maxProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
];

pub(super) fn validate_tool_schema(schema: &Value, label: &str) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{label} must be an object schema"))?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!("{label} must declare object type"));
    }
    let mut literal_nodes = 0usize;
    validate_schema_literal_surface(schema, label, 0, &mut literal_nodes)?;
    let mut nodes = 0usize;
    validate_schema(schema, label, 0, &mut nodes)
}

pub(super) fn validate_instance(schema: &Value, instance: &Value) -> Result<(), String> {
    let mut budget = ValidationBudget::new();
    count_instance_nodes(instance, 0, &mut budget)?;
    validate_value(schema, instance, "$", 0, &mut budget)
}

/// Derive the model/UI-facing schema without changing the raw schema used for
/// protocol validation. Semantic strings with presentation controls are
/// rejected during schema validation; annotation strings are sanitized here.
pub(super) fn schema_for_display(schema: &Value) -> Value {
    match schema {
        Value::Array(values) => Value::Array(values.iter().map(schema_for_display).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), schema_for_display(value)))
                .collect(),
        ),
        Value::String(value) => Value::String(untrusted_display::sanitize_text(value)),
        Value::Null | Value::Bool(_) | Value::Number(_) => schema.clone(),
    }
}

fn validate_schema(
    schema: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!("{path} exceeds schema depth {MAX_SCHEMA_DEPTH}"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_SCHEMA_NODES {
        return Err(format!("schema exceeds {MAX_SCHEMA_NODES} nodes"));
    }
    if schema.is_boolean() {
        return Ok(());
    }
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{path} is not a boolean or object schema"))?;
    for keyword in object.keys() {
        if !ALLOWED_KEYWORDS.contains(&keyword.as_str()) {
            return Err(format!("{path} uses unsupported keyword {keyword:?}"));
        }
    }
    validate_annotations(object, path)?;
    if let Some(value) = object.get("type") {
        let kind = value
            .as_str()
            .ok_or_else(|| format!("{path}.type must be a string"))?;
        if !matches!(
            kind,
            "null" | "boolean" | "object" | "array" | "number" | "integer" | "string"
        ) {
            return Err(format!("{path}.type has unsupported value {kind:?}"));
        }
    }
    if let Some(values) = object.get("enum") {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| format!("{path}.enum must be a non-empty array"))?;
        let mut identities = BTreeSet::new();
        for (index, value) in values.iter().enumerate() {
            let identity = schema_value_identity(value, &mut UnlimitedVisits)?;
            if !identities.insert(identity) {
                return Err(format!("{path}.enum contains duplicate values"));
            }
            validate_semantic_string_surface(value, &format!("{path}.enum[{index}]"))?;
        }
    }
    if let Some(value) = object.get("const") {
        validate_semantic_string_surface(value, &format!("{path}.const"))?;
    }
    validate_object_keywords(object, path, depth, nodes)?;
    validate_array_keywords(object, path, depth, nodes)?;
    validate_string_keywords(object, path)?;
    validate_number_keywords(object, path)?;
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(value) = object.get(keyword) {
            let schemas = value
                .as_array()
                .filter(|schemas| !schemas.is_empty())
                .ok_or_else(|| format!("{path}.{keyword} must be a non-empty array"))?;
            for (index, child) in schemas.iter().enumerate() {
                validate_schema(
                    child,
                    &format!("{path}.{keyword}[{index}]"),
                    depth + 1,
                    nodes,
                )?;
            }
        }
    }
    if let Some(child) = object.get("not") {
        validate_schema(child, &format!("{path}.not"), depth + 1, nodes)?;
    }
    Ok(())
}

/// JSON Schema profile v1 deliberately rejects decimal/exponent literals in
/// schemas. serde_json represents those literals as f64 unless its
/// crate-wide `arbitrary_precision` feature is enabled; accepting them here
/// would make the wire value already rounded before comparison.
fn validate_schema_literal_surface(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!("{path} exceeds schema depth {MAX_SCHEMA_DEPTH}"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_SCHEMA_NODES {
        return Err(format!("schema exceeds {MAX_SCHEMA_NODES} values"));
    }
    match value {
        Value::Number(number) if number.is_f64() => Err(format!(
            "{path} uses an unsupported decimal/exponent number; schema profile v1 only accepts i64/u64 numbers"
        )),
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_schema_literal_surface(
                    child,
                    &format!("{path}[{index}]"),
                    depth + 1,
                    nodes,
                )?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, child) in values {
                if untrusted_display::sanitize_single_line(key) != *key {
                    return Err(format!(
                        "{path} contains unsafe presentation controls in an object key"
                    ));
                }
                validate_schema_literal_surface(
                    child,
                    &format!("{path}[{key:?}]"),
                    depth + 1,
                    nodes,
                )?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_annotations(object: &Map<String, Value>, path: &str) -> Result<(), String> {
    for keyword in ["$schema", "$id", "title", "description"] {
        if object.get(keyword).is_some_and(|value| !value.is_string()) {
            return Err(format!("{path}.{keyword} must be a string"));
        }
    }
    if object
        .get("examples")
        .is_some_and(|value| !value.is_array())
    {
        return Err(format!("{path}.examples must be an array"));
    }
    for keyword in ["deprecated", "readOnly", "writeOnly"] {
        if object.get(keyword).is_some_and(|value| !value.is_boolean()) {
            return Err(format!("{path}.{keyword} must be a boolean"));
        }
    }
    Ok(())
}

fn validate_object_keywords(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if let Some(value) = object.get("properties") {
        let properties = value
            .as_object()
            .ok_or_else(|| format!("{path}.properties must be an object"))?;
        for (name, child) in properties {
            if untrusted_display::sanitize_single_line(name) != *name {
                return Err(format!(
                    "{path}.properties contains unsafe presentation controls in a property name"
                ));
            }
            validate_schema(
                child,
                &format!("{path}.properties[{name:?}]"),
                depth + 1,
                nodes,
            )?;
        }
    }
    if let Some(value) = object.get("required") {
        let required = value
            .as_array()
            .ok_or_else(|| format!("{path}.required must be an array"))?;
        let mut names = BTreeSet::new();
        for value in required {
            let name = value
                .as_str()
                .ok_or_else(|| format!("{path}.required values must be strings"))?;
            if untrusted_display::sanitize_single_line(name) != name {
                return Err(format!(
                    "{path}.required contains unsafe presentation controls"
                ));
            }
            if !names.insert(name) {
                return Err(format!("{path}.required contains duplicate {name:?}"));
            }
        }
    }
    if let Some(child) = object.get("additionalProperties") {
        if !child.is_boolean() && !child.is_object() {
            return Err(format!(
                "{path}.additionalProperties must be a boolean or schema"
            ));
        }
        validate_schema(
            child,
            &format!("{path}.additionalProperties"),
            depth + 1,
            nodes,
        )?;
    }
    validate_nonnegative_pair(object, path, "minProperties", "maxProperties")
}

fn validate_array_keywords(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if let Some(child) = object.get("items") {
        validate_schema(child, &format!("{path}.items"), depth + 1, nodes)?;
    }
    if object
        .get("uniqueItems")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(format!("{path}.uniqueItems must be a boolean"));
    }
    validate_nonnegative_pair(object, path, "minItems", "maxItems")
}

fn validate_string_keywords(object: &Map<String, Value>, path: &str) -> Result<(), String> {
    validate_nonnegative_pair(object, path, "minLength", "maxLength")
}

fn validate_number_keywords(object: &Map<String, Value>, path: &str) -> Result<(), String> {
    for keyword in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
        if object.get(keyword).is_some_and(|value| !value.is_number()) {
            return Err(format!("{path}.{keyword} must be a number"));
        }
    }
    if let (Some(minimum), Some(maximum)) = (
        object.get("minimum").and_then(Value::as_number),
        object.get("maximum").and_then(Value::as_number),
    ) {
        if compare_numbers(minimum, maximum)? == Ordering::Greater {
            return Err(format!("{path}.minimum exceeds maximum"));
        }
    }
    Ok(())
}

fn validate_nonnegative_pair(
    object: &Map<String, Value>,
    path: &str,
    minimum: &str,
    maximum: &str,
) -> Result<(), String> {
    let minimum_value = object.get(minimum).map(|value| {
        value
            .as_u64()
            .ok_or_else(|| format!("{path}.{minimum} must be a non-negative integer"))
    });
    let maximum_value = object.get(maximum).map(|value| {
        value
            .as_u64()
            .ok_or_else(|| format!("{path}.{maximum} must be a non-negative integer"))
    });
    let minimum_value = minimum_value.transpose()?;
    let maximum_value = maximum_value.transpose()?;
    if let (Some(minimum_value), Some(maximum_value)) = (minimum_value, maximum_value) {
        if minimum_value > maximum_value {
            return Err(format!("{path}.{minimum} exceeds {maximum}"));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ValidationBudget {
    nodes: usize,
    visits: usize,
    exhausted: bool,
}

impl ValidationBudget {
    fn new() -> Self {
        Self {
            nodes: 0,
            visits: 0,
            exhausted: false,
        }
    }

    fn consume_visit(&mut self, path: &str) -> Result<(), String> {
        self.visits = self.visits.saturating_add(1);
        if self.visits > MAX_VALIDATION_VISITS {
            self.exhausted = true;
            return Err(format!(
                "{path} exceeds validation visit budget {MAX_VALIDATION_VISITS}"
            ));
        }
        Ok(())
    }
}

fn count_instance_nodes(
    value: &Value,
    depth: usize,
    budget: &mut ValidationBudget,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "instance exceeds validation depth {MAX_SCHEMA_DEPTH}"
        ));
    }
    budget.nodes = budget.nodes.saturating_add(1);
    if budget.nodes > MAX_INSTANCE_NODES {
        return Err(format!("instance exceeds node budget {MAX_INSTANCE_NODES}"));
    }
    match value {
        Value::Array(values) => {
            for child in values {
                count_instance_nodes(child, depth + 1, budget)?;
            }
        }
        Value::Object(values) => {
            for child in values.values() {
                count_instance_nodes(child, depth + 1, budget)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_value(
    schema: &Value,
    instance: &Value,
    path: &str,
    depth: usize,
    budget: &mut ValidationBudget,
) -> Result<(), String> {
    budget.consume_visit(path)?;
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path} exceeds validation depth {MAX_SCHEMA_DEPTH}"
        ));
    }
    if let Some(allowed) = schema.as_bool() {
        return allowed
            .then_some(())
            .ok_or_else(|| format!("{path} is rejected by a false schema"));
    }
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{path} uses an invalid schema"))?;
    if let Some(kind) = object.get("type").and_then(Value::as_str) {
        if !matches_type(instance, kind) {
            return Err(format!("{path} must be {kind}"));
        }
    }
    if let Some(values) = object.get("enum").and_then(Value::as_array) {
        let mut matched = false;
        for expected in values {
            if schema_values_equal(expected, instance, budget)? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(format!("{path} is not one of the allowed enum values"));
        }
    }
    if let Some(expected) = object.get("const") {
        if !schema_values_equal(expected, instance, budget)? {
            return Err(format!("{path} does not match const"));
        }
    }
    validate_composition(object, instance, path, depth, budget)?;
    match instance {
        Value::Object(value) => validate_object_value(object, value, path, depth, budget),
        Value::Array(value) => validate_array_value(object, value, path, depth, budget),
        Value::String(value) => validate_string_value(object, value, path),
        Value::Number(value) => validate_number_value(object, value, path),
        Value::Null | Value::Bool(_) => Ok(()),
    }
}

fn validate_composition(
    schema: &Map<String, Value>,
    instance: &Value,
    path: &str,
    depth: usize,
    budget: &mut ValidationBudget,
) -> Result<(), String> {
    if let Some(schemas) = schema.get("allOf").and_then(Value::as_array) {
        for child in schemas {
            validate_value(child, instance, path, depth + 1, budget)?;
        }
    }
    if let Some(schemas) = schema.get("anyOf").and_then(Value::as_array) {
        let mut matched = false;
        for child in schemas {
            match validate_value(child, instance, path, depth + 1, budget) {
                Ok(()) => {
                    matched = true;
                    break;
                }
                Err(error) if budget.exhausted => return Err(error),
                Err(_) => {}
            }
        }
        if !matched {
            return Err(format!("{path} does not satisfy anyOf"));
        }
    }
    if let Some(schemas) = schema.get("oneOf").and_then(Value::as_array) {
        let mut matches = 0usize;
        for child in schemas {
            match validate_value(child, instance, path, depth + 1, budget) {
                Ok(()) => matches = matches.saturating_add(1),
                Err(error) if budget.exhausted => return Err(error),
                Err(_) => {}
            }
        }
        if matches != 1 {
            return Err(format!("{path} must satisfy exactly one oneOf branch"));
        }
    }
    if let Some(child) = schema.get("not") {
        match validate_value(child, instance, path, depth + 1, budget) {
            Ok(()) => return Err(format!("{path} satisfies a forbidden not schema")),
            Err(error) if budget.exhausted => return Err(error),
            Err(_) => {}
        }
    }
    Ok(())
}

fn validate_object_value(
    schema: &Map<String, Value>,
    instance: &Map<String, Value>,
    path: &str,
    depth: usize,
    budget: &mut ValidationBudget,
) -> Result<(), String> {
    check_size_bounds(
        schema,
        instance.len(),
        path,
        "minProperties",
        "maxProperties",
    )?;
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !instance.contains_key(name) {
                return Err(format!("{path} is missing required property {name:?}"));
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (name, value) in instance {
        let child_path = format!("{path}/{}", escape_pointer(name));
        if let Some(child) = properties.and_then(|properties| properties.get(name)) {
            validate_value(child, value, &child_path, depth + 1, budget)?;
        } else if let Some(additional) = additional {
            validate_value(additional, value, &child_path, depth + 1, budget)?;
        }
    }
    Ok(())
}

fn validate_array_value(
    schema: &Map<String, Value>,
    instance: &[Value],
    path: &str,
    depth: usize,
    budget: &mut ValidationBudget,
) -> Result<(), String> {
    check_size_bounds(schema, instance.len(), path, "minItems", "maxItems")?;
    if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
        if instance.len() > MAX_UNIQUE_ITEMS {
            return Err(format!(
                "{path} exceeds uniqueItems limit {MAX_UNIQUE_ITEMS}"
            ));
        }
        let mut identities = BTreeSet::new();
        for value in instance {
            let identity = schema_value_identity(value, budget)?;
            if !identities.insert(identity) {
                return Err(format!("{path} contains duplicate array items"));
            }
        }
    }
    if let Some(items) = schema.get("items") {
        for (index, value) in instance.iter().enumerate() {
            validate_value(items, value, &format!("{path}/{index}"), depth + 1, budget)?;
        }
    }
    Ok(())
}

fn validate_string_value(
    schema: &Map<String, Value>,
    instance: &str,
    path: &str,
) -> Result<(), String> {
    check_size_bounds(
        schema,
        instance.chars().count(),
        path,
        "minLength",
        "maxLength",
    )
}

fn validate_number_value(
    schema: &Map<String, Value>,
    instance: &serde_json::Number,
    path: &str,
) -> Result<(), String> {
    check_number_bound(schema, instance, path, "minimum", |ordering| {
        ordering != Ordering::Less
    })?;
    check_number_bound(schema, instance, path, "maximum", |ordering| {
        ordering != Ordering::Greater
    })?;
    check_number_bound(schema, instance, path, "exclusiveMinimum", |ordering| {
        ordering == Ordering::Greater
    })?;
    check_number_bound(schema, instance, path, "exclusiveMaximum", |ordering| {
        ordering == Ordering::Less
    })?;
    Ok(())
}

fn check_number_bound(
    schema: &Map<String, Value>,
    instance: &serde_json::Number,
    path: &str,
    keyword: &str,
    accepts: impl FnOnce(Ordering) -> bool,
) -> Result<(), String> {
    let Some(limit) = schema.get(keyword).and_then(Value::as_number) else {
        return Ok(());
    };
    if !accepts(compare_numbers(instance, limit)?) {
        return Err(format!("{path} violates {keyword}"));
    }
    Ok(())
}

fn check_size_bounds(
    schema: &Map<String, Value>,
    size: usize,
    path: &str,
    minimum: &str,
    maximum: &str,
) -> Result<(), String> {
    if let Some(limit) = schema.get(minimum).and_then(Value::as_u64) {
        if (size as u64) < limit {
            return Err(format!("{path} violates {minimum}"));
        }
    }
    if let Some(limit) = schema.get(maximum).and_then(Value::as_u64) {
        if (size as u64) > limit {
            return Err(format!("{path} violates {maximum}"));
        }
    }
    Ok(())
}

fn matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value
            .as_number()
            .and_then(|number| DecimalNumber::parse(&number.to_string()).ok())
            .is_some_and(|number| number.is_integer()),
        "string" => value.is_string(),
        _ => false,
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_semantic_string_surface(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(value) => {
            if untrusted_display::sanitize_text(value) != *value {
                return Err(format!(
                    "{path} contains unsafe presentation controls in a semantic string"
                ));
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_semantic_string_surface(value, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if untrusted_display::sanitize_single_line(key) != *key {
                    return Err(format!(
                        "{path} contains unsafe presentation controls in an object key"
                    ));
                }
                validate_semantic_string_surface(value, &format!("{path}[{key:?}]"))?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

trait ValueVisitMeter {
    fn visit(&mut self) -> Result<(), String>;
}

struct UnlimitedVisits;

impl ValueVisitMeter for UnlimitedVisits {
    fn visit(&mut self) -> Result<(), String> {
        Ok(())
    }
}

impl ValueVisitMeter for ValidationBudget {
    fn visit(&mut self) -> Result<(), String> {
        self.consume_visit("instance equality")
    }
}

/// Canonical identity for the JSON Schema value-equality relation. In
/// particular, numeric values compare by mathematical value, so `1`, `1.0`
/// and `1e0` are identical even though serde_json stores them differently.
fn schema_value_identity<M: ValueVisitMeter>(
    value: &Value,
    meter: &mut M,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    append_schema_value_identity(value, meter, &mut output)?;
    Ok(output)
}

fn schema_values_equal<M: ValueVisitMeter>(
    left: &Value,
    right: &Value,
    meter: &mut M,
) -> Result<bool, String> {
    Ok(schema_value_identity(left, meter)? == schema_value_identity(right, meter)?)
}

fn append_schema_value_identity<M: ValueVisitMeter>(
    value: &Value,
    meter: &mut M,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    meter.visit()?;
    match value {
        Value::Null => output.push(b'n'),
        Value::Bool(false) => output.push(b'f'),
        Value::Bool(true) => output.push(b't'),
        Value::Number(number) => {
            output.push(b'd');
            let number = DecimalNumber::parse(&number.to_string())?;
            output.push(u8::from(number.negative));
            output.extend_from_slice(&number.exponent.to_be_bytes());
            append_length(output, number.digits.len());
            output.extend_from_slice(&number.digits);
        }
        Value::String(value) => {
            output.push(b's');
            append_bytes(output, value.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'a');
            append_length(output, values.len());
            for child in values {
                append_schema_value_identity(child, meter, output)?;
            }
        }
        Value::Object(values) => {
            output.push(b'o');
            append_length(output, values.len());
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (key, child) in entries {
                append_bytes(output, key.as_bytes());
                append_schema_value_identity(child, meter, output)?;
            }
        }
    }
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    append_length(output, bytes.len());
    output.extend_from_slice(bytes);
}

fn append_length(output: &mut Vec<u8>, length: usize) {
    output.extend_from_slice(&(length as u64).to_be_bytes());
}

fn compare_numbers(
    left: &serde_json::Number,
    right: &serde_json::Number,
) -> Result<Ordering, String> {
    let left = DecimalNumber::parse(&left.to_string())?;
    let right = DecimalNumber::parse(&right.to_string())?;
    Ok(left.cmp(&right))
}

/// Exact decimal identity for the finite JSON number serialized by
/// `serde_json::Number`. This avoids silently rounding u64/i64 values through
/// f64 while enforcing schema bounds.
#[derive(Debug, Eq, PartialEq)]
struct DecimalNumber {
    negative: bool,
    digits: Vec<u8>,
    exponent: i64,
}

impl DecimalNumber {
    fn parse(text: &str) -> Result<Self, String> {
        let (negative, text) = text
            .strip_prefix('-')
            .map_or((false, text), |text| (true, text));
        let (mantissa, exponent) =
            text.split_once(['e', 'E'])
                .map_or(Ok((text, 0i64)), |(mantissa, exponent)| {
                    exponent
                        .parse::<i64>()
                        .map(|exponent| (mantissa, exponent))
                        .map_err(|_| "JSON number exponent is out of range".to_owned())
                })?;
        let (whole, fraction) = mantissa
            .split_once('.')
            .map_or((mantissa, ""), |parts| parts);
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("JSON number has an invalid decimal representation".to_owned());
        }
        let mut digits = whole
            .bytes()
            .chain(fraction.bytes())
            .skip_while(|byte| *byte == b'0')
            .map(|byte| byte - b'0')
            .collect::<Vec<_>>();
        if digits.is_empty() {
            return Ok(Self {
                negative: false,
                digits: vec![0],
                exponent: 0,
            });
        }
        let mut exponent = exponent
            .checked_sub(fraction.len() as i64)
            .ok_or_else(|| "JSON number exponent is out of range".to_owned())?;
        while digits.len() > 1 && digits.last() == Some(&0) {
            digits.pop();
            exponent = exponent
                .checked_add(1)
                .ok_or_else(|| "JSON number exponent is out of range".to_owned())?;
        }
        Ok(Self {
            negative,
            digits,
            exponent,
        })
    }

    fn is_integer(&self) -> bool {
        self.digits == [0] || self.exponent >= 0
    }

    fn cmp(&self, other: &Self) -> Ordering {
        if self.digits == [0] && other.digits == [0] {
            return Ordering::Equal;
        }
        match self.negative.cmp(&other.negative) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }
        let absolute = self.cmp_absolute(other);
        if self.negative {
            absolute.reverse()
        } else {
            absolute
        }
    }

    fn cmp_absolute(&self, other: &Self) -> Ordering {
        let self_magnitude = self.digits.len() as i64 + self.exponent;
        let other_magnitude = other.digits.len() as i64 + other.exponent;
        match self_magnitude.cmp(&other_magnitude) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        let length = self.digits.len().max(other.digits.len());
        for index in 0..length {
            let left = self.digits.get(index).copied().unwrap_or(0);
            let right = other.digits.get(index).copied().unwrap_or(0);
            match left.cmp(&right) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn profile_validates_nested_objects_and_closed_properties() {
        let schema = json!({
            "type":"object",
            "properties":{
                "name":{"type":"string","minLength":1},
                "count":{"type":"integer","minimum":1},
                "tags":{"type":"array","items":{"type":"string"},"uniqueItems":true}
            },
            "required":["name","count"],
            "additionalProperties":false
        });
        validate_tool_schema(&schema, "fixture").expect("valid schema");
        validate_instance(&schema, &json!({"name":"ok","count":2,"tags":["a","b"]}))
            .expect("valid instance");
        assert!(validate_instance(&schema, &json!({"name":"","count":0})).is_err());
        assert!(validate_instance(&schema, &json!({"name":"ok","count":2,"extra":true})).is_err());
    }

    #[test]
    fn profile_rejects_unsupported_or_invalid_schema_keywords() {
        for schema in [
            json!({"type":"object","$ref":"#/$defs/value"}),
            json!({"type":"object","properties":[]}),
            json!({"type":"object","required":["x","x"]}),
            json!({"type":"object","minProperties":2,"maxProperties":1}),
        ] {
            assert!(validate_tool_schema(&schema, "fixture").is_err());
        }
    }

    #[test]
    fn profile_applies_composition_and_output_constraints() {
        let schema = json!({
            "type":"object",
            "properties":{
                "state":{"oneOf":[{"const":"open"},{"const":"closed"}]}
            },
            "required":["state"],
            "additionalProperties":false
        });
        validate_tool_schema(&schema, "fixture").expect("valid schema");
        validate_instance(&schema, &json!({"state":"open"})).expect("valid branch");
        assert!(validate_instance(&schema, &json!({"state":"unknown"})).is_err());
    }

    #[test]
    fn numeric_bounds_do_not_round_large_integers_through_f64() {
        let schema = json!({
            "type":"object",
            "properties":{
                "value":{"type":"integer","maximum":9007199254740992u64}
            },
            "required":["value"],
            "additionalProperties":false
        });
        validate_tool_schema(&schema, "fixture").expect("valid numeric schema");
        validate_instance(&schema, &json!({"value":9007199254740992u64}))
            .expect("exact boundary is valid");
        assert!(validate_instance(&schema, &json!({"value":9007199254740993u64})).is_err());
        assert!(matches_type(&json!(1.0), "integer"));
        assert!(!matches_type(&json!(1.5), "integer"));
    }

    #[test]
    fn profile_rejects_wire_decimal_schema_literals_before_comparison() {
        let schema: Value = serde_json::from_str(
            r#"{"type":"object","properties":{"value":{"maximum":9007199254740993.0}}}"#,
        )
        .expect("parse rounded wire schema");
        assert!(
            schema["properties"]["value"]["maximum"]
                .as_number()
                .is_some_and(serde_json::Number::is_f64)
        );
        let error = validate_tool_schema(&schema, "fixture")
            .expect_err("profile v1 must reject decimal schema literals");
        assert!(error.contains("only accepts i64/u64"));

        let exponent_schema: Value =
            serde_json::from_str(r#"{"type":"object","properties":{"value":{"maximum":1e3}}}"#)
                .expect("parse exponent wire schema");
        assert!(validate_tool_schema(&exponent_schema, "fixture").is_err());
    }

    #[test]
    fn schema_value_equality_normalizes_numbers_recursively() {
        let enum_schema = json!({
            "type":"object",
            "properties":{"value":{"enum":[1]}},
            "required":["value"],
            "additionalProperties":false
        });
        validate_tool_schema(&enum_schema, "fixture").expect("valid enum schema");
        validate_instance(&enum_schema, &json!({"value":1.0}))
            .expect("1.0 must equal enum value 1");

        let const_schema = json!({
            "type":"object",
            "properties":{"value":{"const":1}},
            "required":["value"],
            "additionalProperties":false
        });
        validate_instance(&const_schema, &json!({"value":1.0}))
            .expect("1.0 must equal const value 1");

        let unique_schema = json!({
            "type":"object",
            "properties":{"values":{"type":"array","uniqueItems":true}},
            "required":["values"],
            "additionalProperties":false
        });
        let duplicate = json!({
            "values":[
                {"number":1,"nested":[2.0]},
                {"nested":[2],"number":1.0}
            ]
        });
        assert!(validate_instance(&unique_schema, &duplicate).is_err());
        validate_instance(
            &unique_schema,
            &json!({"values":[{"number":1},{"number":2.0}]}),
        )
        .expect("distinct recursive values remain unique");

        let mut meter = UnlimitedVisits;
        assert!(
            schema_values_equal(
                &json!({"a":[1, {"b":2.0}]}),
                &json!({"a":[1.0, {"b":2}]}),
                &mut meter,
            )
            .expect("compare recursive values")
        );
    }

    #[test]
    fn instance_nodes_and_unique_items_are_bounded() {
        let oversized = Value::Array(vec![Value::Null; MAX_INSTANCE_NODES]);
        let error = validate_instance(&Value::Bool(true), &oversized)
            .expect_err("instance node budget must fail closed");
        assert!(error.contains("node budget"));

        let unique = json!({"type":"array","uniqueItems":true});
        let values = Value::Array(
            (0..=MAX_UNIQUE_ITEMS)
                .map(|value| Value::from(value as u64))
                .collect(),
        );
        let error = validate_instance(&unique, &values)
            .expect_err("uniqueItems item budget must fail closed");
        assert!(error.contains("uniqueItems limit"));

        let repeated_array_schema = json!({
            "allOf": (0..64)
                .map(|_| json!({"type":"array","items":true}))
                .collect::<Vec<_>>()
        });
        let repeated_instance = Value::Array(vec![Value::Null; 1024]);
        let error = validate_instance(&repeated_array_schema, &repeated_instance)
            .expect_err("composition must consume the shared visit budget");
        assert!(error.contains("visit budget"));
    }

    #[test]
    fn semantic_schema_strings_reject_controls_and_annotations_are_sanitized() {
        for schema in [
            json!({"type":"object","properties":{"bad\u{202e}key":{"type":"string"}}}),
            json!({"type":"object","properties":{"value":{"enum":["safe\u{200b}hidden"]}}}),
            json!({"type":"object","properties":{"value":{"const":{"bad\u{202e}key":1}}}}),
            json!({"type":"object","default":{"safe\u{202e}hidden":1}}),
            json!({"type":"object","examples":[{"zero\u{200b}width":1}]}),
        ] {
            assert!(validate_tool_schema(&schema, "fixture").is_err());
        }

        let schema = json!({
            "type":"object",
            "description":"visible\u{202e}hidden",
            "properties":{"value":{"type":"string","title":"zero\u{200b}width"}}
        });
        validate_tool_schema(&schema, "fixture").expect("annotation controls are non-semantic");
        let display = schema_for_display(&schema);
        assert_eq!(display["description"], "visible�hidden");
        assert_eq!(display["properties"]["value"]["title"], "zero�width");
        assert_eq!(schema["description"], "visible\u{202e}hidden");
    }
}
