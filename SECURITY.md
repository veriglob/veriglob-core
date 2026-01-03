Security Policy
Supported Versions

Veriglob is under active development.

Version Supported
main branch ✅ Yes
Tagged releases ✅ Yes
Older commits ❌ No

Security fixes are applied only to supported versions.

Reporting a Vulnerability

We take security vulnerabilities very seriously, especially given the sensitive nature of decentralised identity systems.

✅ Please report security issues privately

Do NOT open a public GitHub issue for security vulnerabilities.

Instead, report responsibly using one of the following channels:

📧 Email: security@veriglob.org

🔐 PGP (optional): Available upon request

Include as much detail as possible:

Affected component or module

Steps to reproduce

Potential impact

Suggested mitigation (if known)

⏱ Response Timeline

We aim to follow this timeline:

Acknowledgement: within 48 hours

Initial assessment: within 5 business days

Fix or mitigation: as soon as reasonably possible

Public disclosure: coordinated after fix is released

🛡️ Security Scope

The following are in scope:

DID methods (e.g. did:key, future methods)

Key generation & cryptographic operations

Credential issuance & verification logic

Consent, revocation, and access control logic

APIs, SDKs, and CLI tools

The following are out of scope:

Third-party dependencies (report upstream)

Misconfiguration by integrators

Social engineering attacks

🔑 Cryptography Policy

Veriglob follows modern cryptographic best practices:

Strong, well-reviewed algorithms only

No custom cryptography

Clear separation of public vs private material

Private keys never leave user control

Cryptographic changes are treated as breaking changes and reviewed carefully.

🧪 Security Testing

We actively encourage:

Static analysis

Dependency scanning

Fuzzing

Independent audits

Security tests may be included in CI pipelines where applicable.

🤝 Responsible Disclosure

We welcome and appreciate responsible security research.

Researchers who follow this policy:

Will be credited (if desired)

Will not face legal action

Help strengthen the ecosystem

⚠️ Disclaimer

Veriglob is provided “as is”, without warranty of any kind.

Integrators are responsible for:

Proper configuration

Secure key management

Regulatory compliance in their jurisdiction

📜 License & Ethics

Security research conducted in good faith is encouraged.
Any exploitation beyond proof-of-concept is strictly prohibited.

🔐 Trust is not a feature — it’s the foundation.

Thank you for helping keep Veriglob secure.
