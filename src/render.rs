use std::time::Duration;

use serde_json::Value;

use crate::agent::TurnOutcome;
use crate::types::ToolCall;
use crate::untrusted_display::is_presentation_control;

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
    truncate_for_display(&escape_terminal(&rendered), DISPLAY_VALUE_LIMIT)
}

/// A bounded, terminal-safe preview, not an executable tool payload. Only
/// crate-owned completion observers can see it, after the outcome is durable.
#[derive(Debug)]
pub(crate) struct EditDiffDisplay {
    plain: String,
}

impl EditDiffDisplay {
    pub(crate) fn from_call(call: &ToolCall) -> Option<Self> {
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
        Some(Self {
            plain: truncate_for_display(&diff, DISPLAY_DIFF_LIMIT),
        })
    }

    pub(crate) fn render(&self, options: RenderOptions) -> String {
        if options.color {
            color_replacement_lines(&self.plain)
        } else {
            self.plain.clone()
        }
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
                "context approx {}/0 (invalid)",
                format_number(context.estimated_tokens)
            ),
            Some(window) => {
                let percent = context.estimated_tokens.saturating_mul(100) / window;
                format!(
                    "context approx {}/{} ({}%, {} reserved)",
                    format_number(context.estimated_tokens),
                    format_number(window),
                    percent,
                    format_number(context.reserve_tokens)
                )
            }
            None => format!(
                "context approx {}/unlimited",
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
    escape_terminal_with_layout(value, false)
}

/// Render prose/code without executing terminal or Unicode presentation
/// controls. Preserve tabs/newlines, normalize CRLF, and expose bare CRs.
/// This representation is display-only, never a Provider/journal projection.
pub(crate) fn escape_terminal_multiline(value: &str) -> String {
    escape_terminal_with_layout(value, true)
}

fn escape_terminal_with_layout(value: &str, multiline: bool) -> String {
    let mut escaped = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' if multiline && characters.peek() == Some(&'\n') => {
                characters.next();
                escaped.push('\n');
            }
            '\n' | '\t' if multiline => escaped.push(character),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if is_presentation_control(character) => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

/// Bound the final UTF-8 display bytes, including the truncation marker.
pub(crate) fn truncate_for_display(value: &str, limit: usize) -> String {
    const MARKER: &str = "...<truncated>";
    if value.len() <= limit {
        return value.to_owned();
    }
    if limit < MARKER.len() {
        return MARKER[..limit].to_owned();
    }
    let mut boundary = limit - MARKER.len();
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}{MARKER}", &value[..boundary])
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
                character if is_presentation_control(character) => {
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

fn color_replacement_lines(diff: &str) -> String {
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
    output
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
        let suffix = "...<truncated>";
        assert_eq!(truncate_for_display("abcdef", 6), "abcdef");
        assert_eq!(truncate_for_display("abcdef", 3), "...");
        assert_eq!(truncate_for_display("abcdef", 0), "");
        assert_eq!(
            truncate_for_display(&"abcdef".repeat(10), 3 + suffix.len()),
            "abc...<truncated>"
        );
        assert_eq!(
            truncate_for_display(&"ab中cd".repeat(10), 4 + suffix.len()),
            "ab...<truncated>"
        );
    }

    #[test]
    fn multiline_terminal_text_preserves_layout_without_carriage_return_overwrite() {
        let source = "heading\r\n\t中文🙂\nlast\rreplacement";
        assert_eq!(
            escape_terminal_multiline(source),
            "heading\n\t中文🙂\nlast\\rreplacement"
        );
        assert_eq!(
            escape_terminal(source),
            "heading\\r\\n\\t中文🙂\\nlast\\rreplacement"
        );
    }

    #[test]
    fn terminal_renderers_make_presentation_controls_visible() {
        for control in [
            '\0',
            '\u{1b}',
            '\r',
            '\u{0007}',
            '\u{0008}',
            '\u{007f}',
            '\u{009b}',
            '\u{202e}',
            '\u{2066}',
            '\u{200b}',
            '\u{e0001}',
        ] {
            let source = format!("before{control}after");
            for rendered in [escape_terminal(&source), escape_terminal_multiline(&source)] {
                assert!(!rendered.contains(control));
                assert!(rendered.starts_with("before\\"));
                assert!(rendered.ends_with("after"));
            }
            assert!(
                source.contains(control),
                "rendering must not mutate the source"
            );
        }
    }

    #[test]
    fn terminal_text_is_not_subject_to_diagnostic_preview_truncation() {
        let source = format!("{}tail\u{1b}[2J", "正文\n".repeat(20_000));
        let rendered = escape_terminal_multiline(&source);
        assert_eq!(rendered, format!("{}tail\\x1b[2J", "正文\n".repeat(20_000)));
        assert!(!rendered.contains("<truncated>"));
    }

    #[test]
    fn tool_value_display_escapes_controls_before_applying_its_byte_budget() {
        let value = json!({"text": "中文\u{009b}31m\u{202e}\u{200b}\x1b[2J"});
        let original = value.clone();
        let rendered = display_value(&value);
        assert!(rendered.contains("中文\\u{009b}31m\\u{202e}\\u{200b}\\u001b[2J"));
        assert!(!rendered.chars().any(is_presentation_control));
        assert_eq!(value, original);

        let value = json!({"text": "\u{202e}".repeat(600)});
        assert!(serde_json::to_string(&value).unwrap().len() < DISPLAY_VALUE_LIMIT);
        let rendered = display_value(&value);
        assert!(rendered.len() <= DISPLAY_VALUE_LIMIT);
        assert!(rendered.ends_with("...<truncated>"));
        assert!(!rendered.chars().any(is_presentation_control));
    }

    #[test]
    fn edit_diff_escapes_unicode_controls_in_paths_and_replacements() {
        let call = ToolCall {
            id: "hidden-call-id".to_owned(),
            name: "edit".to_owned(),
            arguments: json!({
                "path": "src/\u{202e}file\u{009b}.rs",
                "old_text": "old\u{200b}\u{009b}\u{202e}",
                "new_text": "new\u{2066}\x1b[2J",
            }),
        };
        let plain = EditDiffDisplay::from_call(&call)
            .unwrap()
            .render(RenderOptions { color: false });
        assert!(plain.starts_with("--- src/\\u{202e}file\\u{009b}.rs\n"));
        assert!(plain.contains("-old\\u{200b}\\u{009b}\\u{202e}\n"));
        assert!(plain.contains("+new\\u{2066}\\x1b[2J\n"));
        assert!(
            !plain
                .chars()
                .any(|c| is_presentation_control(c) && c != '\n')
        );
        assert!(!plain.contains("hidden-call-id"));
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
        let plain = EditDiffDisplay::from_call(&call)
            .unwrap()
            .render(RenderOptions { color: false });
        assert!(!plain.contains('\u{1b}'));
        assert!(plain.contains("-\\x1b[31m"));

        let colored = EditDiffDisplay::from_call(&call)
            .unwrap()
            .render(RenderOptions { color: true });
        assert!(colored.starts_with("--- src/main.rs\n+++ src/main.rs\n"));
        assert!(colored.contains("\x1b[31m-old\x1b[0m\n"));
        assert!(colored.contains("\x1b[32m+new\x1b[0m\n"));
    }

    #[test]
    fn edit_diff_preview_is_bounded_after_escaping_and_color_always_resets() {
        let call = ToolCall {
            id: "must-not-be-displayed".to_owned(),
            name: "edit".to_owned(),
            arguments: json!({
                "path": "file.txt",
                "old_text": "old\r\n\ttext",
                "new_text": "中文\u{202e}\x1b[31m\n".repeat(DISPLAY_DIFF_LIMIT),
                "expected_sha256": "must-not-be-displayed",
            }),
        };
        let preview = EditDiffDisplay::from_call(&call).unwrap();
        let plain = preview.render(RenderOptions { color: false });
        assert!(plain.len() <= DISPLAY_DIFF_LIMIT);
        assert!(plain.ends_with("...<truncated>"));
        assert!(!plain.contains("must-not-be-displayed"));
        assert!(plain.contains("-old\\r\n-\ttext\n"));
        assert!(
            !plain
                .chars()
                .any(|c| is_presentation_control(c) && !matches!(c, '\n' | '\t'))
        );
        let colored = preview.render(RenderOptions { color: true });
        assert!(colored.ends_with(RESET));
        assert_eq!(
            colored
                .replace(RED, "")
                .replace(GREEN, "")
                .replace(RESET, ""),
            plain
        );
    }

    #[test]
    fn edit_diff_preview_requires_edit_and_complete_string_fields() {
        for (name, arguments) in [
            (
                "write",
                json!({"path": "file.txt", "old_text": "old", "new_text": "new"}),
            ),
            ("edit", json!({"path": "file.txt", "old_text": "old"})),
            (
                "edit",
                json!({"path": 42, "old_text": "old", "new_text": "new"}),
            ),
        ] {
            assert!(
                EditDiffDisplay::from_call(&ToolCall {
                    id: "call-1".to_owned(),
                    name: name.to_owned(),
                    arguments,
                })
                .is_none()
            );
        }
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
        assert!(rendered.contains("context approx 45,000/128,000 (35%, 16,384 reserved)"));
    }
}
