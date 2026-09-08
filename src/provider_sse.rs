use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseEvent {
    pub(crate) event: String,
    pub(crate) data: String,
    pub(crate) id: Arc<str>,
    pub(crate) retry: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SseLimits {
    pub(crate) max_line_bytes: usize,
    pub(crate) max_event_bytes: usize,
    pub(crate) max_frames: usize,
    pub(crate) max_stream_bytes: usize,
    /// The Provider never uses SSE `id` for replay. Keep the optional
    /// metadata bounded anyway: otherwise a single legal `id:` line could
    /// consume the whole event ceiling and sit in `last_event_id` while the
    /// response-level retained budget remains unaware of it.
    pub(crate) max_event_id_bytes: usize,
}

impl SseLimits {
    pub(crate) const fn new(
        max_line_bytes: usize,
        max_event_bytes: usize,
        max_frames: usize,
        max_stream_bytes: usize,
    ) -> Self {
        Self {
            max_line_bytes,
            max_event_bytes,
            max_frames,
            max_stream_bytes,
            // Four KiB is ample for a replay cursor and keeps metadata from
            // becoming an unaccounted response-sized allocation. Callers
            // that intentionally exercise a different profile can override
            // this with `with_event_id_limit`.
            max_event_id_bytes: if max_line_bytes < 4 * 1024 {
                max_line_bytes
            } else {
                4 * 1024
            },
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_event_id_limit(mut self, maximum_bytes: usize) -> Self {
        self.max_event_id_bytes = maximum_bytes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SseDecodeError {
    LineTooLarge { limit: usize },
    EventTooLarge { limit: usize },
    TooManyFrames { limit: usize },
    StreamTooLarge { limit: usize },
    InvalidUtf8,
    EventIdTooLarge { limit: usize },
    DecoderFinished,
    DecoderFailed,
}

impl fmt::Display for SseDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLarge { limit } => {
                write!(formatter, "SSE line exceeds the {limit}-byte limit")
            }
            Self::EventTooLarge { limit } => {
                write!(formatter, "SSE event exceeds the {limit}-byte limit")
            }
            Self::TooManyFrames { limit } => {
                write!(formatter, "SSE stream exceeds the {limit}-frame limit")
            }
            Self::StreamTooLarge { limit } => {
                write!(formatter, "SSE stream exceeds the {limit}-byte limit")
            }
            Self::InvalidUtf8 => formatter.write_str("SSE stream is not valid UTF-8"),
            Self::EventIdTooLarge { limit } => {
                write!(formatter, "SSE event id exceeds the {limit}-byte limit")
            }
            Self::DecoderFinished => formatter.write_str("SSE decoder has already finished"),
            Self::DecoderFailed => formatter.write_str("SSE decoder has already failed"),
        }
    }
}

impl std::error::Error for SseDecodeError {}

#[derive(Debug)]
pub(crate) enum SseFeedError<E> {
    Decode(SseDecodeError),
    Handler(E),
}

impl<E: fmt::Display> fmt::Display for SseFeedError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::Handler(error) => error.fmt(formatter),
        }
    }
}

impl<E> From<SseDecodeError> for SseFeedError<E> {
    fn from(error: SseDecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Incremental SSE decoder whose allocation boundary is the raw byte stream.
///
/// Raw-byte limits are charged before a byte is retained. `max_event_bytes`
/// counts the complete wire representation of the current frame, including
/// line endings, so an endpoint cannot postpone the limit check by withholding
/// the blank line that dispatches an event. Empty frames consume both the
/// stream-byte and frame-count budgets.
pub(crate) struct BoundedSseDecoder {
    limits: SseLimits,
    line: Vec<u8>,
    event_bytes: usize,
    frames: usize,
    stream_bytes: usize,
    pending_cr: bool,
    at_stream_start: bool,
    data: String,
    event_type: String,
    last_event_id: Arc<str>,
    retry: Option<Duration>,
    finished: bool,
    failed: bool,
}

impl BoundedSseDecoder {
    pub(crate) fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            line: Vec::new(),
            event_bytes: 0,
            frames: 0,
            stream_bytes: 0,
            pending_cr: false,
            at_stream_start: true,
            data: String::new(),
            event_type: String::new(),
            last_event_id: Arc::from(""),
            retry: None,
            finished: false,
            failed: false,
        }
    }

    pub(crate) fn push_chunk<E>(
        &mut self,
        chunk: &[u8],
        mut on_event: impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        self.ensure_live().map_err(SseFeedError::Decode)?;

        let result = self.push_chunk_inner(chunk, &mut on_event);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(crate) fn finish<E>(
        &mut self,
        mut on_event: impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        self.ensure_live().map_err(SseFeedError::Decode)?;

        let result = self.finish_inner(&mut on_event);
        match result {
            Ok(()) => {
                self.finished = true;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    fn push_chunk_inner<E>(
        &mut self,
        chunk: &[u8],
        on_event: &mut impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        for &byte in chunk {
            if self.pending_cr {
                if byte == b'\n' {
                    self.charge_raw_byte()?;
                    self.pending_cr = false;
                    self.finish_line(on_event)?;
                    continue;
                }

                self.pending_cr = false;
                self.finish_line(on_event)?;
            }

            match byte {
                b'\r' => {
                    self.charge_raw_byte()?;
                    self.pending_cr = true;
                }
                b'\n' => {
                    self.charge_raw_byte()?;
                    self.finish_line(on_event)?;
                }
                _ => {
                    self.charge_raw_byte()?;
                    if self.line.len() == self.limits.max_line_bytes {
                        return Err(SseDecodeError::LineTooLarge {
                            limit: self.limits.max_line_bytes,
                        }
                        .into());
                    }
                    self.line.push(byte);
                }
            }
        }

        Ok(())
    }

    fn finish_inner<E>(
        &mut self,
        on_event: &mut impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        // A lone CR is itself a valid SSE line ending. It is held for one
        // byte of look-ahead so CRLF can be charged as one delimiter; at EOF
        // that pending CR must still finish its line. This matters for a
        // terminal encoded as `data: ...\r\r`: the second CR is the blank-line
        // delimiter and must dispatch the frame. After flushing it, any
        // remaining non-empty data frame is genuinely unterminated and is
        // discarded rather than being promoted to execution authority.
        if self.pending_cr {
            self.pending_cr = false;
            self.finish_line(on_event)?;
        }
        self.line.clear();
        self.data.clear();
        self.event_type.clear();
        self.retry = None;
        self.event_bytes = 0;
        Ok(())
    }

    fn charge_raw_byte<E>(&mut self) -> Result<(), SseFeedError<E>> {
        if self.stream_bytes == self.limits.max_stream_bytes {
            return Err(SseDecodeError::StreamTooLarge {
                limit: self.limits.max_stream_bytes,
            }
            .into());
        }
        if self.event_bytes == self.limits.max_event_bytes {
            return Err(SseDecodeError::EventTooLarge {
                limit: self.limits.max_event_bytes,
            }
            .into());
        }
        self.stream_bytes += 1;
        self.event_bytes += 1;
        Ok(())
    }

    fn finish_line<E>(
        &mut self,
        on_event: &mut impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        let line = std::str::from_utf8(&self.line).map_err(|_| SseDecodeError::InvalidUtf8)?;
        let line = if self.at_stream_start {
            self.at_stream_start = false;
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };

        if line.is_empty() {
            self.line.clear();
            self.complete_frame(on_event)?;
            self.event_bytes = 0;
            return Ok(());
        }

        if !line.starts_with(':') {
            let (field, mut value) = line.split_once(':').unwrap_or((line, ""));
            if let Some(without_space) = value.strip_prefix(' ') {
                value = without_space;
            }

            match field {
                "data" => {
                    self.data.push_str(value);
                    self.data.push('\n');
                }
                "event" => self.event_type = value.to_owned(),
                "id" if !value.contains('\0') => {
                    if value.len() > self.limits.max_event_id_bytes {
                        return Err(SseDecodeError::EventIdTooLarge {
                            limit: self.limits.max_event_id_bytes,
                        }
                        .into());
                    }
                    self.last_event_id = Arc::from(value);
                }
                "retry" if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                    if let Ok(milliseconds) = value.parse::<u64>() {
                        self.retry = Some(Duration::from_millis(milliseconds));
                    }
                }
                _ => {}
            }
        }

        self.line.clear();
        Ok(())
    }

    fn complete_frame<E>(
        &mut self,
        on_event: &mut impl FnMut(SseEvent) -> Result<(), E>,
    ) -> Result<(), SseFeedError<E>> {
        if self.frames == self.limits.max_frames {
            return Err(SseDecodeError::TooManyFrames {
                limit: self.limits.max_frames,
            }
            .into());
        }
        self.frames += 1;

        if self.data.is_empty() {
            self.event_type.clear();
            self.retry = None;
            return Ok(());
        }

        if self.data.ends_with('\n') {
            self.data.pop();
        }
        let event = SseEvent {
            event: if self.event_type.is_empty() {
                "message".to_owned()
            } else {
                std::mem::take(&mut self.event_type)
            },
            data: std::mem::take(&mut self.data),
            // The SSE last-event ID persists across frames. Sharing its
            // immutable allocation avoids replay-amplifying one large `id:`
            // line into a fresh allocation for every later data frame.
            id: Arc::clone(&self.last_event_id),
            retry: self.retry.take(),
        };
        on_event(event).map_err(SseFeedError::Handler)
    }

    fn ensure_live(&self) -> Result<(), SseDecodeError> {
        if self.failed {
            Err(SseDecodeError::DecoderFailed)
        } else if self.finished {
            Err(SseDecodeError::DecoderFinished)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_line_bytes: usize, max_event_bytes: usize) -> SseLimits {
        SseLimits::new(max_line_bytes, max_event_bytes, usize::MAX, usize::MAX)
    }

    fn collect(
        decoder: &mut BoundedSseDecoder,
        chunk: &[u8],
        events: &mut Vec<SseEvent>,
    ) -> Result<(), SseFeedError<()>> {
        decoder.push_chunk(chunk, |event| {
            events.push(event);
            Ok(())
        })
    }

    #[test]
    fn parses_fields_comments_crlf_and_chunk_boundaries() {
        let mut decoder = BoundedSseDecoder::new(limits(64, 256));
        let mut events = Vec::new();

        for chunk in [
            &b"\xef\xbb"[..],
            &b"\xbfid: first\r"[..],
            &b"\n: keepalive\r\nevent: answer\r\nretry: 125\r\ndata: one\r\n"[..],
            &b"data:two\r\n\r"[..],
            &b"\ndata: next\n\n"[..],
        ] {
            collect(&mut decoder, chunk, &mut events).unwrap();
        }

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "answer");
        assert_eq!(events[0].data, "one\ntwo");
        assert_eq!(&*events[0].id, "first");
        assert_eq!(events[0].retry, Some(Duration::from_millis(125)));
        assert_eq!(events[1].event, "message");
        assert_eq!(events[1].data, "next");
        assert_eq!(&*events[1].id, "first");
    }

    #[test]
    fn rejects_an_oversized_last_event_id_before_retaining_it() {
        let decoder = SseLimits::new(1024, 4096, 8, 16 * 1024).with_event_id_limit(8);
        let mut decoder = BoundedSseDecoder::new(decoder);
        let error = decoder
            .push_chunk(b"id: 123456789\n\n", |_| Ok::<_, ()>(()))
            .unwrap_err();
        assert!(matches!(
            error,
            SseFeedError::Decode(SseDecodeError::EventIdTooLarge { limit: 8 })
        ));
        assert!(matches!(
            decoder.push_chunk(b"", |_| Ok::<_, ()>(())),
            Err(SseFeedError::Decode(SseDecodeError::DecoderFailed))
        ));
    }

    #[test]
    fn rejects_unterminated_line_before_a_delimiter_arrives() {
        let mut decoder = BoundedSseDecoder::new(limits(8, 128));
        decoder
            .push_chunk(&b"data: 12"[..], |_| Ok::<_, ()>(()))
            .unwrap();
        let error = decoder
            .push_chunk(&b"3"[..], |_| Ok::<_, ()>(()))
            .unwrap_err();

        assert!(matches!(
            error,
            SseFeedError::Decode(SseDecodeError::LineTooLarge { limit: 8 })
        ));
        assert!(matches!(
            decoder.push_chunk(&[], |_| Ok::<_, ()>(())),
            Err(SseFeedError::Decode(SseDecodeError::DecoderFailed))
        ));
    }

    #[test]
    fn rejects_event_across_chunks_before_a_blank_line_arrives() {
        let mut decoder = BoundedSseDecoder::new(limits(16, 15));
        decoder
            .push_chunk(&b"data:a\n"[..], |_| Ok::<_, ()>(()))
            .unwrap();
        decoder
            .push_chunk(&b"data:b\n"[..], |_| Ok::<_, ()>(()))
            .unwrap();
        let error = decoder
            .push_chunk(&b"xy"[..], |_| Ok::<_, ()>(()))
            .unwrap_err();

        assert!(matches!(
            error,
            SseFeedError::Decode(SseDecodeError::EventTooLarge { limit: 15 })
        ));
    }

    #[test]
    fn crlf_split_across_chunks_is_one_line_ending() {
        let mut decoder = BoundedSseDecoder::new(limits(32, 64));
        let mut events = Vec::new();
        collect(&mut decoder, b"data: value\r", &mut events).unwrap();
        collect(&mut decoder, b"\n\r", &mut events).unwrap();
        assert!(events.is_empty());
        collect(&mut decoder, b"\n", &mut events).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "value");
    }

    #[test]
    fn finish_discards_unterminated_final_event() {
        let mut decoder = BoundedSseDecoder::new(limits(64, 128));
        let mut events = Vec::new();
        collect(&mut decoder, b"event: answer\ndata: final", &mut events).unwrap();
        assert!(events.is_empty());
        decoder
            .finish(|event| {
                events.push(event);
                Ok::<_, ()>(())
            })
            .unwrap();

        assert!(events.is_empty());
        assert!(matches!(
            decoder.finish(|_| Ok::<_, ()>(())),
            Err(SseFeedError::Decode(SseDecodeError::DecoderFinished))
        ));
    }

    #[test]
    fn finish_flushes_a_lone_cr_line_ending_before_discarding_pending_data() {
        let mut decoder = BoundedSseDecoder::new(SseLimits::new(64, 128, 4, 256));
        let mut events = Vec::new();
        decoder
            .push_chunk(b"data: answer\r\r", |event| {
                events.push(event);
                Ok::<_, ()>(())
            })
            .unwrap();
        decoder
            .finish(|event| {
                events.push(event);
                Ok::<_, ()>(())
            })
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "answer");

        // A single CR after a non-empty data line terminates that line but
        // does not provide the blank line required to dispatch the frame.
        let mut truncated = BoundedSseDecoder::new(limits(64, 128));
        let mut truncated_events = Vec::new();
        truncated
            .push_chunk(b"data: answer\r", |event| {
                truncated_events.push(event);
                Ok::<_, ()>(())
            })
            .unwrap();
        truncated
            .finish(|event| {
                truncated_events.push(event);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(truncated_events.is_empty());
    }

    #[test]
    fn invalid_utf8_fails_closed_only_after_a_line_is_terminated() {
        let mut newline_decoder = BoundedSseDecoder::new(limits(64, 128));
        assert!(matches!(
            newline_decoder.push_chunk(b"data: \xff\n", |_| Ok::<_, ()>(())),
            Err(SseFeedError::Decode(SseDecodeError::InvalidUtf8))
        ));

        let mut eof_decoder = BoundedSseDecoder::new(limits(64, 128));
        eof_decoder
            .push_chunk(b"data: \xff", |_| Ok::<_, ()>(()))
            .unwrap();
        eof_decoder.finish(|_| Ok::<_, ()>(())).unwrap();
    }

    #[test]
    fn handler_failure_poison_decoder() {
        let mut decoder = BoundedSseDecoder::new(limits(64, 128));
        let error = decoder
            .push_chunk(b"data: value\n\n", |_| Err("stop"))
            .unwrap_err();
        assert!(matches!(error, SseFeedError::Handler("stop")));
        assert!(matches!(
            decoder.push_chunk(b"data: later\n\n", |_| Ok::<_, ()>(())),
            Err(SseFeedError::Decode(SseDecodeError::DecoderFailed))
        ));
    }

    #[test]
    fn empty_keepalive_frames_consume_the_frame_budget() {
        let mut decoder = BoundedSseDecoder::new(SseLimits::new(16, 16, 2, 64));
        decoder.push_chunk(b"\n\n", |_| Ok::<_, ()>(())).unwrap();
        let error = decoder.push_chunk(b"\n", |_| Ok::<_, ()>(())).unwrap_err();

        assert!(matches!(
            error,
            SseFeedError::Decode(SseDecodeError::TooManyFrames { limit: 2 })
        ));
    }

    #[test]
    fn stream_byte_budget_accumulates_across_completed_frames() {
        let mut decoder = BoundedSseDecoder::new(SseLimits::new(16, 16, 8, 4));
        decoder
            .push_chunk(b"\n\n\n\n", |_| Ok::<_, ()>(()))
            .unwrap();
        let error = decoder.push_chunk(b"\n", |_| Ok::<_, ()>(())).unwrap_err();

        assert!(matches!(
            error,
            SseFeedError::Decode(SseDecodeError::StreamTooLarge { limit: 4 })
        ));
    }
}
