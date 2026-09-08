//! Partial completion accounting shared by the raw block probe and host tests.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompletionState {
    pub remaining: u32,
    pub error: i32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcessCompletion;
impl CompletionState {
    pub const fn new(bytes: u32) -> Self {
        Self {
            remaining: bytes,
            error: 0,
        }
    }
    /// True only when all issue bytes have completed. Caller removes the state
    /// after true; a request pointer is not itself a permanent lifetime identity.
    pub fn advance(&mut self, bytes: u32, error: i32) -> Result<bool, ExcessCompletion> {
        if bytes > self.remaining {
            return Err(ExcessCompletion);
        }
        self.remaining -= bytes;
        if self.error == 0 {
            self.error = error;
        }
        Ok(self.remaining == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_reads_finish_only_after_all_bytes() {
        let mut s = CompletionState::new(65536);
        assert_eq!(s.advance(16384, 0), Ok(false));
        assert_eq!(s.advance(32768, 0), Ok(false));
        assert_eq!(s.advance(16384, 0), Ok(true));
        assert_eq!(s.remaining, 0);
    }
    #[test]
    fn keeps_first_failure_across_parts() {
        let mut s = CompletionState::new(8192);
        assert_eq!(s.advance(4096, -5), Ok(false));
        assert_eq!(s.advance(4096, 0), Ok(true));
        assert_eq!(s.error, -5);
    }
    #[test]
    fn rejects_excess_without_mutation() {
        let mut s = CompletionState::new(4096);
        assert_eq!(s.advance(8192, -5), Err(ExcessCompletion));
        assert_eq!(s.remaining, 4096);
        assert_eq!(s.error, 0);
    }
    #[test]
    fn zero_byte_command_completes() {
        assert_eq!(CompletionState::new(0).advance(0, 0), Ok(true));
    }
    #[test]
    fn zero_progress_is_not_completion() {
        assert_eq!(CompletionState::new(4096).advance(0, 0), Ok(false));
    }
}
