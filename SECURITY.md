# Security Policy

## Supported versions

Only the latest 0.5.x release receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue.

- GitHub Security Advisories:
  https://github.com/Aditya-Prakash14/opensecuritybot/security/advisories/new
- Email: ap312038@gmail.com

Include the affected version, a description of the issue, and the impact you
believe it has.

## What counts

- A bypass of the scope guard that lets out-of-scope findings reach the LLM.
- Command injection or arbitrary argv execution through a scan skill.
- A break of the prompt-injection boundary between scanner data and instructions.
- Exposure of secrets: API keys, configuration files, or environment values.
- Path traversal or writes outside the intended workspace or output directory.

## What to leave out of a report

Never include client engagement data, finding evidence, API keys, or npm tokens
in a report. Redact anything sensitive and use synthetic reproduction data
instead. A report that contains live credentials or client data will be deleted
without being read.

## Response expectations

- Acknowledgement within 3 business days.
- Triage and an initial assessment within 7 business days.
- Coordinated disclosure: we agree on a publication date with you after a fix
  is available, and credit you unless you ask otherwise.

This project does not offer a bug bounty and cannot promise payment for reports.
