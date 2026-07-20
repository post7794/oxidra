use std::time::Duration;

use serde_json::Value;

use crate::agent::TurnOutcome;
use crate::types::ToolCall;

const DISPLAY_VALUE_LIMIT: usize = 4 * 1024;
const DISPLAY_DIFF_LIMIT: usize = 16 * 1024;
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RenderOptions {
    pub color: bool,
}

pub(crate) fn display_value(value: &Value) -> String {
    let rendered = serde_json::to_string(value).unwrap_or_else(|_| "<invalid JSON>".to_owned());
    truncate_for_display(&rendered, DISPLAY_VALUE_LIMIT)
}

pub(crate) fn render_edit_diff(call: &ToolCall, options: RenderOptions) -> Option<String> {
    if call.name != "edit" {
        return None;
    }
    let path = call.arguments.get("path")?.as_str()?;
    let old_text = call.arguments.get("old_text")?.as_str()?;
    let new_text = call.arguments.get("new_text")?.as_str()?;
    let mut diff = format!(
        "--- {}\n+++ {}\n@@ exact replacement @@\n",
        escape_terminal(path),
        escape_terminal(path)
    );
    append_diff_lines(&mut diff, '-', old_text);
    append_diff_lines(&mut diff, '+', new_text);
    let diff = truncate_for_display(&diff, DISPLAY_DIFF_LIMIT);
    if options.color {
        color_replacement_lines(&diff)
    } else {
        Some(diff)
    }
}

pub(crate) fn format_turn_metrics(outcome: &TurnOutcome, elapsed: Duration, model: &str) -> String {
    let stalled = if outcome.stalled { ", stalled" } else { "" };
    let cached = if outcome.usage.cached_input_tokens > 0 {
        format!(
            ", cached {}",
            format_number(outcome.usage.cached_input_tokens)
        )
    } else {
        String::new()
    };
    let reasoning = if outcome.usage.reasoning_output_tokens > 0 {
        format!(
            ", reasoning {}",
            format_number(outcome.usage.reasoning_output_tokens)
        )
    } else {
        String::new()
    };
    let context = match &outcome.context {
        Some(context) => match context.context_window {
            Some(0) => format!(
                "context {}/0 (invalid)",
                format_number(context.estimated_tokens)
            ),
            Some(window) => {
                let percent = context.estimated_tokens.saturating_mul(100) / window;
                format!(
                    "context {}/{} ({}%, {} reserved)",
                    format_number(context.estimated_tokens),
                    format_number(window),
                    percent,
                    format_number(context.reserve_tokens)
                )
            }
            None => format!(
                "context {}/unlimited",
                format_number(context.estimated_tokens)
            ),
        },
        None => "context unavailable".to_owned(),
    };

    format!(
        "[turn] {} response(s), {} tool call(s), {:.1}s{} | model {} | tokens in {}{}, out {}{}, total {} | {}",
        outcome.responses,
        outcome.tools,
        elapsed.as_secs_f64(),
        stalled,
        escape_terminal(model),
        format_number(outcome.usage.input_tokens),
        cached,
        format_number(outcome.usage.output_tokens),
        reasoning,
        format_number(outcome.usage.total_tokens),
        context
    )
}

pub(crate) fn escape_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn truncate_for_display(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let boundary = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= limit)
        .last()
        .unwrap_or(0);
    format!("{}...<truncated>", &value[..boundary])
}

fn append_diff_lines(output: &mut String, marker: char, text: &str) {
    if text.is_empty() {
        output.push(marker);
        output.push('\n');
        return;
    }
    for line in text.split_inclusive('\n') {
        output.push(marker);
        for character in line.chars() {
            match character {
                '\n' => output.push('\n'),
                '\r' => output.push_str("\\r"),
                '\t' => output.push('\t'),
                '\u{1b}' => output.push_str("\\x1b"),
                character if character.is_control() => {
                    use std::fmt::Write as _;
                    let _ = write!(output, "\\u{{{:04x}}}", character as u32);
                }
                character => output.push(character),
            }
        }
        if !line.ends_with('\n') {
            output.push('\n');
        }
    }
}

fn color_replacement_lines(diff: &str) -> Option<String> {
    let mut output = String::with_capacity(diff.len() + 64);
    for (index, line) in diff.split_inclusive('\n').enumerate() {
        let color = if index >= 3 {
            match line.as_bytes().first() {
                Some(b'-') => Some(RED),
                Some(b'+') => Some(GREEN),
                _ => None,
            }
        } else {
            None
        };
        if let Some(color) = color {
            output.push_str(color);
            output.push_str(line.strip_suffix('\n').unwrap_or(line));
            output.push_str(RESET);
            if line.ends_with('\n') {
                output.push('\n');
            }
        } else {
            output.push_str(line);
        }
    }
    Some(output)
}

fn format_number(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            output.push(',');
        }
        output.push(character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::ContextEstimate;
    use crate::types::Usage;
    use serde_json::json;

    #[test]
    fn truncation_keeps_utf8_valid() {
        assert_eq!(truncate_for_display("abcdef", 3), "abc...<truncated>");
        assert_eq!(truncate_for_display("ab中cd", 4), "ab...<truncated>");
    }

    #[test]
    fn edit_diff_colors_only_replacement_lines() {
        let call = ToolCall {
            id: "call-1".to_owned(),
            name: "edit".to_owned(),
            arguments: json!({
                "path": "src/main.rs",
                "old_text": "old\n\u{1b}[31m",
                "new_text": "new\n",
            }),
        };
        let plain = render_edit_diff(&call, RenderOptions { color: false }).unwrap();
        assert!(!plain.contains('\u{1b}'));
        assert!(plain.contains("-\\x1b[31m"));

        let colored = render_edit_diff(&call, RenderOptions { color: true }).unwrap();
        assert!(colored.starts_with("--- src/main.rs\n+++ src/main.rs\n"));
        assert!(colored.contains("\x1b[31m-old\x1b[0m\n"));
        assert!(colored.contains("\x1b[32m+new\x1b[0m\n"));
    }

    #[test]
    fn formats_usage_and_context_metrics() {
        let outcome = TurnOutcome {
            responses: 2,
            tools: 1,
            usage: Usage {
                input_tokens: 1_200,
                cached_input_tokens: 200,
                output_tokens: 300,
                reasoning_output_tokens: 50,
                total_tokens: 1_500,
            },
            context: Some(ContextEstimate {
                estimated_tokens: 45_000,
                context_window: Some(128_000),
                reserve_tokens: 16_384,
            }),
            ..TurnOutcome::default()
        };
        let rendered = format_turn_metrics(&outcome, Duration::from_millis(1250), "gpt-test");
        assert!(rendered.contains("model gpt-test"));
        assert!(
            rendered.contains("tokens in 1,200, cached 200, out 300, reasoning 50, total 1,500")
        );
        assert!(rendered.contains("context 45,000/128,000 (35%, 16,384 reserved)"));
    }
}
