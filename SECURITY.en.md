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
