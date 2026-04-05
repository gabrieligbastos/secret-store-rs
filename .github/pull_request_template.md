# Which issue does this PR close?

<!--
Link the related issue using GitHub syntax, e.g. `Closes #123`
-->

Closes #.

# Rationale for this change

<!--
Why is this change needed? If the issue already explains it clearly, this section can be brief.
-->

# What changes are included in this PR?

<!--
Summarise the individual changes, especially if the diff is large.
-->

# Are there any user-facing changes?

<!--
If yes, update CHANGELOG.md under `## [Unreleased]` before requesting review.
If there are breaking changes to the public API, call them out explicitly here.
-->

# Checklist

- [ ] Tests added / updated for new behaviour
- [ ] `cargo test --all-features` passes locally
- [ ] `cargo clippy --all-features -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo deny check` passes
- [ ] `typos` passes
- [ ] `CHANGELOG.md` updated (if user-facing change)
