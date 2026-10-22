# Contributing

Bug reports, hub test results and pull requests are welcome.

- **Run the tests** before sending a change: `tests/setup-tools.sh` once (it
  downloads a pinned JDK and Groovy 2.4 into the git-ignored `.tools/`), then
  `tests/run.sh`. CI runs the same suite.
- **Hubitat runs Groovy 2.4** in a sandbox. Stay with plain loops and the
  classes the driver already imports. `tests/CompileCheck.groovy` refuses the
  usual traps (post-2.4 methods, `System.`, non-ASCII).
- **Protocol changes** need a test. Crypto changes must keep
  `tests/CryptoTest.groovy` passing byte for byte; regenerate the reference
  transcript with `tests/fixtures/noise_vectors.py` if you extend it.
- **Releases**: `scripts/release.sh X.Y.Z "notes"` stamps the version in the
  driver and the HPM manifest. Add user-visible changes to CHANGELOG.md.
- Never paste an API key in an issue, a log or a test fixture.
