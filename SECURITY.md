# 安全策略

这个插件会接触 SSH 凭据（密码、私钥、sudo 密码），安全问题请优先私下报告，不要直接开公开 issue：

- 通过 GitHub 的 [Private vulnerability reporting](https://github.com/wybiacx/dsh-remote-bash/security/advisories/new) 提交；
- 或者直接联系仓库维护者。

报告时请附：DSH 版本、插件版本、复现步骤、影响范围。收到后会尽快确认并给出修复计划。

已知的边界（不属于漏洞，但使用前应该知道）：

- DSH 凭据库是文件存储（`~/.dsh/.credentials.yaml`，0600）。同一 OS 用户下的进程，包括 Agent 的 shell 工具，理论上可以读到该文件；插件无法在文件权限之外进一步隔离。
- 插件会把命令和输出写进当前会话记录，这是 DSH 的工作方式，请勿在命令里写明文密码。
- 主机指纹采用 TOFU：首次连接自动信任并记录，之后指纹变化会被拒绝。首次连接时如果网络已被劫持，TOFU 无法提供保护。
