# Security Policy
1: # Security Policy
2: 
3: ## Supported Versions
4: 
5: We take the security of `authcore` seriously. Only the latest minor release receives security fixes.
6: 
7: | Version | Supported |
8: | ------- | --------- |
9: | latest  | ✅        |
10: | < latest| ❌        |
11: 
12: Once the library reaches a stable `v1.0.0`, a formal support window will be defined here.
13: 
14: ## Reporting a Vulnerability
15: 
16: **Do not open a public GitHub issue for security vulnerabilities.**
17: 
18: Please report security issues by using [GitHub private vulnerability reporting](https://github.com/Jaro-c/authcore/security/advisories/new).
19: 
20: Alternatively, you can contact the maintainers directly at [INSERT EMAIL OR SECURITY ADDRESS].
21: 
22: Include as much of the following as you can:
23: 
24: - A clear description of the vulnerability.
25: - Steps to reproduce or a minimal proof-of-concept (PoC).
26: - The affected version(s).
27: - Any known mitigations or workarounds.
28: 
29: You will receive an acknowledgement within **72 hours**. We aim to release a patch within **14 days** for confirmed critical issues and **30 days** for non-critical ones.
30: 
31: We will credit reporters in the release notes unless you prefer to remain anonymous.
32: 
33: ## Scope
34: 
35: This policy covers the `github.com/Jaro-c/authcore` module and all sub-packages published under this repository (`auth/jwt`, `auth/apikey`, `auth/oauth`, etc.).
36: 
37: Third-party dependencies are out of scope. Please report those issues to their respective maintainers.
38: 
39: ## Disclosure Policy
40: 
41: We follow a coordinated disclosure model:
42: 
43: 1. Reporter submits the vulnerability privately.
44: 2. Maintainers confirm and reproduce the issue.
45: 3. A fix is developed in a private branch.
46: 4. A patched release is published.
47: 5. A public security advisory is opened with full details.
48: 
49: ## Security Best Practices for Users
50: 
51: - Always use the latest published version of `authcore`.
52: - Pin dependencies with `go.sum` and verify checksums via the Go module proxy.
53: - Never disable signature verification or skip TLS in production configurations.
54: - Follow the principle of least privilege when configuring API keys and tokens.

