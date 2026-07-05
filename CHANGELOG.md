# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-06

### Added
- Initial release of `website-compliance-guardian` Claude Code Skill
- **SKILL.md** — main entry point, always-on activation rules, 12-dimension verification framework
- **security.md** — OWASP Top 10 coverage, cookies security, authentication patterns, CSRF protection, rate limiting, HTTP security headers
- **gdpr.md** — full RGPD compliance (UE 2016/679), Loi Informatique et Libertés, ePrivacy directive, CNIL recommendations, 8 rights implementation
- **backend.md** — API route structure, Zod validation, route consistency checking, IDOR prevention, webhook signature verification, cron job security
- **frontend.md** — form validation (client + server), type-safe API client, XSS prevention, storage rules, accessibility (RGAA 4.1), UX security patterns
- **checks.md** — pre-delivery checklist with 3 severity levels (critical / high / low), ESLint security config, GitHub Actions CI workflow
- **examples.md** — 15 detailed bug examples with automatic corrections covering OWASP A01-A10, RGPD, CSRF, IDOR, XSS, open redirect
- **README.md** — installation, usage, supported stacks, FR/UE compliance references
- **LICENSE** — MIT
- Support for Next.js App Router, Next.js Pages Router, Express, Fastify, React (Vite/CRA)
- French and European legal priority (RGPD, CNIL, RGAA, Loi pour une République Numérique)
