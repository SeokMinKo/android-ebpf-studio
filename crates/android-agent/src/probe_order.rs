/// Install the mandatory block pair through one fail-fast sequence.
pub fn attach_block_pair<E>(
    mut attach: impl FnMut(&'static str) -> Result<(), E>,
) -> Result<(), E> {
    attach("block_rq_complete")?;
    attach("block_rq_issue")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_completion_during_issue_attachment_is_observed() {
        let mut completion_active = false;
        let mut issued = 0;
        let mut completed = 0;
        attach_block_pair(|probe| {
            if probe == "block_rq_complete" {
                completion_active = true;
            }
            if probe == "block_rq_issue" {
                // A real request can finish before the next attach syscall.
                issued += 1;
                if completion_active {
                    completed += 1;
                }
            }
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(issued, 1);
        assert_eq!(
            completed, issued,
            "an accepted issue must already have a completion observer"
        );
    }
}
