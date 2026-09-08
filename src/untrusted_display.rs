//! Rendering-only sanitization for text controlled by external processes.
//!
//! Protocol data must remain byte-for-byte available for validation, hashing
//! and journaling. These helpers are used only when text crosses into a human
//! or model-facing display surface.

use serde_json::Value;

pub(crate) const MAX_UNTRUSTED_JSON_DISPLAY_BYTES: usize = 16 * 1024;

pub(crate) fn sanitize_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        if character == '\n' {
            output.push('\n');
        } else if is_presentation_control(character) {
            output.push('�');
        } else {
            output.push(character);
        }
    }
    output
}

pub(crate) fn sanitize_single_line(input: &str) -> String {
    sanitize_text(input).replace('\n', "�")
}

pub(crate) fn text_for_display(input: &str) -> String {
    let mut output = String::with_capacity(input.len().min(MAX_UNTRUSTED_JSON_DISPLAY_BYTES));
    for character in input.chars() {
        let character = if is_presentation_control(character) {
            '�'
        } else {
            character
        };
        if output.len() + character.len_utf8() > MAX_UNTRUSTED_JSON_DISPLAY_BYTES {
            return truncated_utf8_prefix(&output, MAX_UNTRUSTED_JSON_DISPLAY_BYTES);
        }
        output.push(character);
    }
    output
}

pub(crate) fn quoted_single_line(input: &str) -> String {
    format!("{:?}", sanitize_single_line(input))
}

// A sanitized Unicode scalar occupies at least one byte and its source at
// most four. This prefix is therefore enough to reproduce the original
// sanitize-then-truncate result without serializing the entire JSON tree.
const MAX_RAW_JSON_DISPLAY_BYTES: usize = MAX_UNTRUSTED_JSON_DISPLAY_BYTES * 4;
const MAX_JSON_DISPLAY_DEPTH: usize = 128;

#[derive(Default)]
struct JsonDisplayWriter {
    bytes: Vec<u8>,
    truncated: bool,
}

impl std::io::Write for JsonDisplayWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = MAX_RAW_JSON_DISPLAY_BYTES.saturating_sub(self.bytes.len());
        let written = available.min(bytes.len());
        if written < bytes.len() {
            self.truncated = true;
            if written == 0 {
                return Err(std::io::Error::other("JSON display prefix is full"));
            }
        }
        self.bytes.extend_from_slice(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn json_for_display(value: &Value) -> String {
    // Public rendering helpers accept borrowed Values, not only wire-parsed
    // MCP results. Bound recursion before entering serde's serializer.
    if crate::session::validate_borrowed_json_depth_v1(
        value,
        MAX_JSON_DISPLAY_DEPTH,
        "display",
        "external JSON",
    )
    .is_err()
    {
        return "<external JSON exceeds display depth limit>".to_owned();
    }
    let mut writer = JsonDisplayWriter::default();
    if serde_json::to_writer(&mut writer, value).is_err() && !writer.truncated {
        return "<unserializable external JSON>".to_owned();
    }
    // Only a capped prefix may end partway through UTF-8. That replacement is
    // beyond the final display cutoff and cannot change the visible prefix.
    text_for_display(&String::from_utf8_lossy(&writer.bytes))
}

pub(crate) fn truncate_utf8(text: &str, maximum_bytes: usize) -> String {
    if text.len() <= maximum_bytes {
        return text.to_owned();
    }
    truncated_utf8_prefix(text, maximum_bytes)
}

fn truncated_utf8_prefix(text: &str, maximum_bytes: usize) -> String {
    let suffix = "<truncated>";
    let mut end = maximum_bytes.saturating_sub(suffix.len()).min(text.len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut output = text[..end].to_owned();
    output.push_str(suffix);
    output
}

/// Unicode code points that can alter visual ordering, line structure or
/// glyph boundaries without appearing as ordinary printable text.
pub(crate) fn is_presentation_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{ffa0}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sanitizer_removes_controls_without_mutating_source_data() {
        let source = "safe\u{202e}hidden\u{200b}\nnext";
        assert_eq!(sanitize_text(source), "safe�hidden�\nnext");
        assert_eq!(sanitize_single_line(source), "safe�hidden��next");
        assert_eq!(source, "safe\u{202e}hidden\u{200b}\nnext");
    }

    #[test]
    fn json_display_is_bounded_and_terminal_safe() {
        let value = serde_json::json!({"message": format!("\u{202e}{}", "x".repeat(20000))});
        let rendered = json_for_display(&value);
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.ends_with("<truncated>"));
        assert!(rendered.len() <= MAX_UNTRUSTED_JSON_DISPLAY_BYTES);
    }

    #[test]
    fn bounded_display_preserves_sanitize_then_truncate_semantics() {
        for text in [
            "plain".repeat(20_000),
            "中🙂\u{202e}\u{e0001}\n\t\0\\\"".repeat(20_000),
            "x".repeat(MAX_UNTRUSTED_JSON_DISPLAY_BYTES),
            format!("{}🙂", "x".repeat(MAX_UNTRUSTED_JSON_DISPLAY_BYTES - 1)),
        ] {
            assert_eq!(
                text_for_display(&text),
                truncate_utf8(
                    &sanitize_single_line(&text),
                    MAX_UNTRUSTED_JSON_DISPLAY_BYTES
                ),
            );
            let value = serde_json::json!({"text": text});
            let previous = truncate_utf8(
                &sanitize_single_line(&serde_json::to_string(&value).unwrap()),
                MAX_UNTRUSTED_JSON_DISPLAY_BYTES,
            );
            assert_eq!(json_for_display(&value), previous);
        }
        let wide = Value::Array(vec![Value::Null; 40_000]);
        assert_eq!(
            json_for_display(&wide),
            truncate_utf8(
                &serde_json::to_string(&wide).unwrap(),
                MAX_UNTRUSTED_JSON_DISPLAY_BYTES
            ),
        );
    }

    #[test]
    fn json_display_writer_stops_at_fixed_prefix_capacity() {
        let value = Value::String("x".repeat(MAX_RAW_JSON_DISPLAY_BYTES * 2));
        let mut writer = JsonDisplayWriter::default();
        assert!(serde_json::to_writer(&mut writer, &value).is_err());
        assert!(writer.truncated);
        assert_eq!(writer.bytes.len(), MAX_RAW_JSON_DISPLAY_BYTES);
    }

    #[test]
    fn untrusted_text_display_is_single_line_and_bounded() {
        let rendered = text_for_display(&format!("safe\u{202e}\n{}", "x".repeat(20000)));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\n'));
        assert!(rendered.ends_with("<truncated>"));
        assert!(rendered.len() <= MAX_UNTRUSTED_JSON_DISPLAY_BYTES);
    }
}
