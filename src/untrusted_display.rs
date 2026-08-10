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
    truncate_utf8(
        &sanitize_single_line(input),
        MAX_UNTRUSTED_JSON_DISPLAY_BYTES,
    )
}

pub(crate) fn quoted_single_line(input: &str) -> String {
    format!("{:?}", sanitize_single_line(input))
}

pub(crate) fn json_for_display(value: &Value) -> String {
    let serialized = serde_json::to_string(value)
        .unwrap_or_else(|_| "<unserializable external JSON>".to_owned());
    truncate_utf8(
        &sanitize_single_line(&serialized),
        MAX_UNTRUSTED_JSON_DISPLAY_BYTES,
    )
}

pub(crate) fn truncate_utf8(text: &str, maximum_bytes: usize) -> String {
    if text.len() <= maximum_bytes {
        return text.to_owned();
    }
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
fn is_presentation_control(character: char) -> bool {
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
    fn untrusted_text_display_is_single_line_and_bounded() {
        let rendered = text_for_display(&format!("safe\u{202e}\n{}", "x".repeat(20000)));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\n'));
        assert!(rendered.ends_with("<truncated>"));
        assert!(rendered.len() <= MAX_UNTRUSTED_JSON_DISPLAY_BYTES);
    }
}
