# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-07-06

### Added — Renforcement suite à usage réel Next.js + Prisma + Vercel + Neon

#### Nouveau fichier `false-positives.md`
- 40+ patterns qui semblent sécurisés mais ne le sont pas en réalité
- Tableau structuré : Pattern / Semble OK / Problème réel / Correction attendue
- Couvre : rate limit en mémoire, rate limit basé sur cookie, `===` pour password, `maxAge` sur cookie admin, `.env*` sans `!.env.example`, route publique check auth, `localStorage` pour token, JWT sans `expiresIn`, bcrypt cost 10, `Math.random()`, etc.

#### SKILL.md — RÈGLE D'OR obligatoire et non-contournable
- Nouvelle section "RÈGLE D'OR — OBLIGATOIRE ET NON-CONTOURNABLE"
- 5 étapes obligatoires avant tout retour de code web (ouvrir checks.md, vérifier qualité, consulter false-positives.md, pièges serverless, ajouter section Compliance Guardian)
- Marqueur de fin obligatoire : la réponse ne peut JAMAIS se terminer sans `🔒 Compliance Guardian`
- Nouvelle section "PRINCIPE FONDAMENTAL — QUALITÉ PAS PRÉSENCE" avec tableau de comparaison
- Frontmatter mis à jour avec `serverless: [vercel, netlify, cloudflare-workers, deno-deploy]`

#### security.md — Nouvelles sections §17 et §18
- §17 "PIÈGES SPÉCIFIQUES AU SERVERLESS" (8 sous-sections) :
  - 17.1 Rate limiting en mémoire = INUTILE (cold start Vercel)
  - 17.2 Rate limit basé sur cookie = contournable
  - 17.3 Sessions en mémoire = perdues
  - 17.4 Files uploadés en `public/` = servis publiquement
  - 17.5 Timeout des fonctions serverless (10s Vercel Hobby)
  - 17.6 Edge Middleware — `jose` au lieu de `jsonwebtoken`
  - 17.7 Variables d'environnement par environnement (Dev/Preview/Prod)
  - 17.8 Logs serverless éphémères (Sentry/Axiom)
- §18 "BRUTE-FORCE PROTECTION — Lockout progressif et persistant" :
  - Schedule de lockout : 3→30s, 5→1min, 7→5min, 10→15min, 15→1h, 20→24h, 25+→permanent
  - 9 règles critiques (DB-based, IP-based, non-contournable, escalade, reset on success, UI countdown, Retry-After, no leak)

#### checks.md — Enrichissement majeur
- Section "Authentification & autorisation" : remplacement de 2 lignes simples par 11 checkpoints détaillés (rate limit persistant, IP-based, lockout progressif, escalade, countdown, Retry-After, no leak)
- Nouvelle section "Rate limiting — QUALITÉ requise" (faux positifs #1 et #2 intégrés)
- Nouvelle section "Brute-force protection — PROGRESSIVE + PERSISTANT" (12 checkpoints)
- Nouvelle section "Serverless pitfalls — Voir security.md §17" (8 checkpoints)
- Template de rapport de vérification enrichi avec sections Serverless et Faux positifs

#### examples.md — EXEMPLES 23 et 24
- EXEMPLE 23 : Progressive lockout persistant (Prisma + Vercel)
  - Pattern de référence complet pour `/api/auth/login`
  - Schéma Prisma `LoginAttempt`
  - Logique de lockout progressif (`LOCKOUT_SCHEDULE`)
  - Route API complète avec `Retry-After`, message neutre, cookie `__Host-`
  - UI React avec countdown
  - Job cron de purge
- EXEMPLE 24 : Route `/api/admin/settings` publique utilisée comme check auth
  - Séparation check auth (`/api/admin/me`) vs données sensibles (`/api/admin/settings`)
  - Jamais de secrets retournés par la route de check

### Changed
- `SKILL.md` description : mention brute-force PROGRESSIF, pièges serverless, faux positifs, qualité pas présence
- `SKILL.md` dimension #8 (rate limiting) enrichie avec exigence DB/Redis + lockout progressif + IP-based
- `SKILL.md` dimension #6 (cookies) enrichie avec "pas de maxAge sur cookie session admin"
- `README.md` caractéristiques mises à jour (vérification obligatoire, qualité pas présence, pièges serverless, brute-force progressif)
- `README.md` structure : ajout du fichier `false-positives.md`
- `README.md` : 22 → 24 exemples

### Fixed — Issues identifiés en usage réel
- Le skill validait la PRÉSENCE d'un rate limit sans vérifier sa QUALITÉ (en mémoire = KO sur Vercel)
- Le skill n'avait pas de mécanisme d'auto-déclenchement (frontmatter `always-on` insuffisant)
- Le skill ne couvrait pas les pièges serverless (cold start, `public/`, Edge runtime)
- Le skill n'avait pas de liste de faux positifs (validait des patterns qui semblent OK mais ne le sont pas)
- Le skill n'exigeait pas la section `🔒 Compliance Guardian` dans toute réponse

## [1.2.0] - 2026-07-06

### Added
- **Nouveau fichier `advanced.md`** (1300+ lignes) regroupant 20 sujets avancés :
  - §1 File upload security (magic bytes, path traversal, SVG XSS, EXIF, stockage privé)
  - §2 MFA / 2FA (TOTP, backup codes, login flow, rate limit OTP)
  - §3 Cookie prefixes (`__Host-`, `__Secure-`)
  - §4 Race conditions (TOCTOU, double-spend, atomicité Prisma)
  - §5 ReDoS (regex catastrophic backtracking)
  - §6 Body size limits & DoS
  - §7 Order injection (sort param)
  - §8 Mass assignment (Prisma)
  - §9 Prototype pollution (lodash.merge, __proto__)
  - §10 WebSocket security (Origin, auth, rate limit)
  - §11 postMessage (origin validation, targetOrigin)
  - §12 Email infrastructure (SPF, DKIM, DMARC, BIMI)
  - §13 Subdomain takeover (CNAME dangling)
  - §14 Subresource Integrity (SRI)
  - §15 Information disclosure (user enumeration, X-Powered-By, source maps, .git/)
  - §16 Cache security (Cache-Control: no-store, Vary: Cookie)
  - §17 OAuth / OIDC (state, PKCE, redirect URI strict, ID token validation)
  - §18 Supply chain (lockfile, audit, branch protection, SBOM, Docker root, install scripts)
  - §19 Build & CI (secrets, signed commits, Dependabot)
  - §20 NEXT_PUBLIC_ leak (vérification bundle après build)

- **7 nouvelles dimensions de vérification** dans `SKILL.md` (14 à 20), portant le total à 20 dimensions
- **Nouvelles sections dans `security.md`** : §11 cookie prefixes, §12 MFA, §13 mass assignment, §14 ReDoS, §15 race conditions, §16 NEXT_PUBLIC_ leak
- **Nouvelles sections dans `backend.md`** : §12 file upload security (deep), §13 WebSocket security, §14 order injection, §15 pagination DoS
- **Nouvelles sections dans `frontend.md`** : §11 postMessage validation, §12 Service Worker security (HTTPS + consent), §13 NEXT_PUBLIC_ leak vérification
- **Nouvelles sections dans `gdpr.md`** : §15 cookie wall interdit (Planet49), §16 DPA Article 28, §17 Article 30 registre des traitements, §18 exemption analytics CNIL (Matomo/Plausible), §19 cross-device tracking
- **EXEMPLES 17 à 22 dans `examples.md`** :
  - EXEMPLE 17 — Upload de SVG avec XSS (magic bytes + UUID + sharp + S3 privé)
  - EXEMPLE 18 — Énumération d'utilisateurs via inscription (message neutre)
  - EXEMPLE 19 — Secret leaked dans NEXT_PUBLIC_ (renommage + vérification bundle)
  - EXEMPLE 20 — Race condition sur coupon (updateMany atomique)
  - EXEMPLE 21 — Cookie wall RGPD (bannière overlay non bloquante)
  - EXEMPLE 22 — postMessage sans validation d'origine (whitelist + Zod + targetOrigin)
- **8 nouvelles checklists dans `checks.md`** : file upload, MFA, info disclosure, race conditions, cookie prefixes/cache, order injection/pagination, cross-origin, supply chain, RGPD avancé

### Changed
- `SKILL.md` description mise à jour avec toutes les nouvelles dimensions
- `README.md` : 13 → 20 dimensions, 16 → 22 exemples, nouveau fichier `advanced.md` dans la structure
- `gdpr.md` : 14 → 19 sections

## [1.1.0] - 2026-07-06

### Added
- **13ème dimension de vérification** : "Navigation légale cohérente" (sitemap / footer / pages légales) dans `SKILL.md`
- **Nouvelle section dans `gdpr.md`** §9 "Navigation légale cohérente" avec :
  - Triplet obligatoire (page physique + footer + sitemap)
  - Liste d'anti-patterns interdits (`/#mentions-legales`, URLs divergentes, pages exclues du sitemap…)
  - Implémentation Next.js App Router (`app/sitemap.ts`, `app/robots.ts`, footer type-safe)
  - URL canonique stable + règle sur `robots.txt`
  - Vérifications automatiques à chaque ajout/retrait de page légale
- **Nouvelle section dans `checks.md`** 🚨 critique "Navigation légale cohérente — Triplet sitemap / footer / pages" (8 checkpoints)
- **EXEMPLE 16 dans `examples.md`** : sitemap et footer désynchronisés des pages légales, avec correction complète (sitemap, footer, canonical, robots.txt)
- Mise à jour des vérifications automatiques RGPD dans `gdpr.md` §14 avec 4 nouveaux checkpoints

### Changed
- Description du skill mise à jour pour mentionner la cohérence navigation légale (sitemap / footer / pages)
- Renumérotation des sections `gdpr.md` §9 → §14 (insertion de la nouvelle section 9)

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
