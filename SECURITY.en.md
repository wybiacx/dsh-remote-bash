# Security Policy

[简体中文](SECURITY.md) · **English**

This plugin handles SSH credentials (passwords, private keys, sudo passwords). Please report security issues privately rather than in a public issue:

- Use GitHub's [private vulnerability reporting](https://github.com/wybiacx/dsh-remote-bash/security/advisories/new);
- or contact the maintainer directly.

Please include: DSH version, plugin version, reproduction steps and impact. We will confirm and propose a fix as soon as possible.

Known boundaries (not vulnerabilities, but worth knowing before use):

- The DSH credential store is file-based (`~/.dsh/.credentials.yaml`, mode 0600). Any process running as the same OS user, including the agent's shell tools, can read that file in principle; the plugin cannot isolate beyond file permissions.
- The plugin writes commands and output into the current session record, which is how DSH works. Do not put plaintext passwords in commands.
- Host keys use TOFU: the first connection is trusted and recorded, later changes are rejected. If the network was already compromised during the first connection, TOFU cannot protect you.

Repaired execution boundaries:

- Sudo passwords are sent through SSH stdin only on authentication prompts; generated command text contains no password and command input is isolated from authentication input.
- First-use host-key comparison and recording are one serialized decision. Approval binds a fixed host snapshot; configuration changes require a new call.
- Downloads validate directory entries and destination paths and do not follow destination-subtree symlinks. This is not a complete filesystem sandbox against a malicious concurrent process running as the same OS user.
- Credential revisions switch at the atomic inventory commit. Failed cleanup remains retryable and does not attach old secrets to a same-name replacement host. A data directory is managed by one Host instance.
- Cancellation stops client waits and further dispatch, but cannot guarantee termination of detached remote processes or undo side effects.
