# Security policy

LibrePatch runs installers as SYSTEM on the computers it manages, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through GitHub:
go to the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting).

Include what you found, how to reproduce it, the version or commit, and what an attacker could do with it.
If you can, say whether you want to be credited.

## What to expect

LibrePatch is maintained by one person in their own time, so these are goals, not guarantees:

- an acknowledgement within about a week;
- a first assessment within about two weeks;
- a fix or a mitigation, and a coordinated public disclosure, as soon as one is ready. Serious problems come first.

Good-faith research on your own installation is welcome. Please do not test against systems you do not own or have
permission to test, and do not access data that is not yours.

## Supported versions

Security fixes go into the latest release and the one before it.

## Background

The threat model, the controls that exist, the evidence for each, and the known gaps and risks are written down in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). LibrePatch has not had an independent security audit; if you review the code, findings
about the areas listed under "known gaps" are especially useful.
