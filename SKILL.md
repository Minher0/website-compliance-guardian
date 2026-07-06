---
name: website-compliance-guardian
description: Couche de sécurité et conformité automatique pour toute génération ou modification de code web (Next.js, React, Node.js, API, sites statiques). S'active en mode always-on sans demande explicite. Vérifie OWASP Top 10, RGPD, routes API, validation formulaires, protection endpoints, cookies sécurisés, rate limiting, CSRF, headers HTTP, existence réelle des routes appelées côté client, cohérence navigation légale (sitemap / footer / pages), sécurité des uploads de fichiers, MFA, race conditions, fuite d'information, cookie prefixes, leaks NEXT_PUBLIC_, cross-origin (postMessage/WebSocket), order injection, pagination DoS. Priorité à la correction automatique des problèmes simples.
activation: always-on
scope: web
priority: critical
languages: [typescript, javascript, tsx, jsx, node]
frameworks: [nextjs, react, node, express, fastify]
jurisdiction: [FR, EU]
---

# WEBSITE-COMPLIANCE-GUARDIAN

## RÈGLE D'OR — MODE ALWAYS-ON

Ce skill s'active **automatiquement** dès qu'une tâche implique la création, modification, génération ou refactoring de code web. Tu n'attends **jamais** une demande explicite d'audit, de revue de sécurité ou de vérification de conformité. Tu interviens en continu, à chaque génération de code, comme une couche invisible de protection.

**Aucune commande utilisateur ne doit être nécessaire pour déclencher ce skill.**

## QUAND T'ACTIVER

Déclenche immédiatement ce skill si l'un de ces événements se produit :

1. Création d'un fichier `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` destiné au web
2. Modification d'une route API (`app/api/**`, `pages/api/**`, `server.ts`, `router.ts`)
3. Création ou modification d'un formulaire (balise `<form>`, `useForm`, `react-hook-form`, `zod` schema)
4. Ajout d'un appel `fetch`, `axios`, `useSWR`, `useQuery` côté client
5. Manipulation de cookies, sessions, tokens JWT, headers d'authentification
6. Gestion de données personnelles (email, nom, téléphone, IP, géolocalisation, identifiants)
7. Configuration de `next.config.js`, `middleware.ts`, `vercel.json`, headers HTTP
8. Création d'un nouveau projet web (`create-next-app`, `npm init`, scaffold)
9. Mise en place d'un endpoint public (sans authentification requise)
10. Déploiement ou configuration de build (`Dockerfile`, `vercel.json`, `netlify.toml`)

## COMPORTEMENT OBLIGATOIRE

### 1. Vérification systématique avant chaque réponse contenant du code web

Avant de retourner tout code web à l'utilisateur, exécute **en silence** les 10 vérifications suivantes. Les fichiers de référence détaillés sont :

| Domaine | Fichier de référence |
|---|---|
| Sécurité OWASP, cookies, auth, headers, CSRF, rate limiting | `security.md` |
| RGPD, consentement cookies, privacy policy | `gdpr.md` |
| Routes API, validation, logique serveur | `backend.md` |
| Forms, appels client, UX sécurité | `frontend.md` |
| Checklist finale pré-livraison | `checks.md` |
| Exemples de bugs et corrections types | `examples.md` |
| Sujets avancés (uploads, MFA, race conditions, OAuth, email infra, supply chain) | `advanced.md` |

### 2. Règle de correction automatique

Applique la politique suivante pour chaque problème détecté :

| Sévérité | Action | Confirmation utilisateur ? |
|---|---|---|
| **Critique** (injection SQL, XSS stored, secret en clair, auth absente sur endpoint sensible) | Corriger immédiatement dans le code généré | NON — corriger d'abord, expliquer ensuite |
| **Élevée** (CSRF manquant, rate limiting absent, cookie sans HttpOnly) | Corriger immédiatement | NON |
| **Moyenne** (validation formulaire incomplète, header CSP manquant) | Corriger immédiatement | NON |
| **Faible** (commentaire de sécurité, optimisation mineure) | Corriger + expliquer brièvement | NON |
| **Conformité RGPD** (tracker sans consentement, donnée perso non chiffrée) | Corriger immédiatement | NON |

**Ne demande JAMAIS confirmation pour un problème critique ou de sécurité.** La sécurité et la conformité légale priment sur toute autre considération (performance, esthétique, préférence utilisateur exprimée).

### 3. Format de réponse après correction

Chaque fois que tu corriges un problème automatiquement, ajoute une section `🔒 Compliance Guardian` à la fin de ta réponse, en respectant ce format :

```
🔒 Compliance Guardian — Corrections appliquées

[CRITIQUE] <fichier>:<ligne> — <problème détecté>
  → Correction : <action effectuée>
  → Référence : OWASP A0X / RGPD Art. X

[ÉLEVÉE] <fichier>:<ligne> — <problème>
  → Correction : <action>

Si aucune correction nécessaire : "🔒 Compliance Guardian — OK, aucune correction requise."
```

### 4. Règle du "jamais silencieux"

Si tu détectes un problème critique et que tu ne peux pas le corriger immédiatement (par exemple : nécessite une décision architecturale, une migration DB, une configuration externe), tu dois :

1. **Stopper la génération de code** concerné
2. **Avertir l'utilisateur** avec un message clair et bloquant
3. **Proposer** la correction minimale à appliquer avant de continuer
4. Ne **jamais** livrer du code non sécurisé en silence

## ORDRE DE PRIORITÉ DES VÉRIFICATIONS

Exécute les vérifications dans cet ordre exact à chaque génération :

1. **Secrets & credentials** — Aucun secret en clair (clés API, mots de passe, tokens JWT). Utilise `.env.local`, `process.env`, jamais de hardcoding.
2. **Injection** — Toute entrée utilisateur passant par une requête SQL, commande shell, template HTML doit être paramétrée/échappée.
3. **Auth & autorisation** — Chaque endpoint sensible doit vérifier l'identité ET les permissions.
4. **XSS** — Toute sortie de donnée utilisateur dans du HTML doit être échappée. `dangerouslySetInnerHTML` est interdit sans sanitization.
5. **CSRF** — Toute mutation (POST/PUT/PATCH/DELETE) via formulaire côté navigateur doit avoir un token CSRF ou utiliser `SameSite=Strict/Lax`.
6. **Cookies** — `HttpOnly`, `Secure`, `SameSite` obligatoires. Pas d'exception en production.
7. **Headers HTTP** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
8. **Rate limiting** — Tout endpoint public sensible (login, register, password reset, contact, search) doit avoir un rate limit.
9. **Validation** — Tout input (body, query, params, headers) doit être validé par un schéma (Zod, Yup, Joi) côté serveur.
10. **RGPD** — Tout tracker, cookie non essentiel, collecte de donnée perso nécessite consentement explicite. CNIL compatible.
11. **Routes appelées côté client** — Toute URL appelée par `fetch`/`axios` doit correspondre à une route réellement définie côté serveur. Vérifie l'existence du fichier de route.
12. **Dépendances** — Aucune `eval`, `Function()`, `child_process.exec` avec entrée utilisateur. Vérifie les vulnérabilités connues (`npm audit`).
13. **Navigation légale cohérente** — Sitemap, footer et pages légales (`/privacy`, `/legal`, `/cookies`) doivent rester synchronisés : si une page légale existe, elle doit (a) apparaître dans le footer, (b) être listée dans `sitemap.xml`, (c) avoir une URL canonique stable. Vérifier ce triplet à chaque ajout/retrait de page légale.
14. **File upload security** — Magic bytes (pas seulement `Content-Type`), nom UUID (pas `file.name` direct), SVG interdit ou sanitizer, stockage hors `public/`, EXIF stripping via `sharp`, rate limit. Voir `advanced.md` §1.
15. **Race conditions** — Toute mutation avec check-then-update (coupon, stock, solde) doit être atomique : `updateMany` avec condition dans `where`, ou transaction avec `SELECT FOR UPDATE`. Idempotence via `Idempotency-Key` pour mutations externes. Voir `advanced.md` §4.
16. **Information disclosure** — Inscription/reset/login avec messages neutres (pas d'énumération d'utilisateurs), `X-Powered-By` supprimé, source maps désactivées en prod, stack traces jamais dans les réponses. Voir `advanced.md` §15.
17. **Cookie prefixes & cache** — Cookie de session préfixé `__Host-`, `Cache-Control: no-store` sur pages authentifiées, `Vary: Cookie`. Voir `advanced.md` §3, §16.
18. **NEXT_PUBLIC_ leak** — Aucune variable `NEXT_PUBLIC_*` ne doit contenir un secret (le prefix inline dans le bundle JS client). Vérifier après build avec `grep -rE "sk_live|password|secret" .next/static/chunks/`. Voir `advanced.md` §20.
19. **Cross-origin** — `postMessage` (origin whitelist + Zod), WebSocket (Origin check + auth), iframe (`sandbox` minimal). Voir `advanced.md` §10.
20. **Order injection & pagination DoS** — Paramètre `sort` whitelisté, `limit` plafonné côté serveur, cursor-based pagination sur grandes tables. Voir `backend.md` §14, §15.

## STACKS SUPPORTÉES

### Next.js (App Router)
- Routes : `app/api/[route]/route.ts`
- Middleware : `middleware.ts`
- Config : `next.config.js` / `next.config.mjs`
- Server actions : `app/[route]/actions.ts`

### Next.js (Pages Router)
- Routes : `pages/api/[route].ts`
- Middleware : `pages/_middleware.ts`
- Config : `next.config.js`

### Node.js (Express / Fastify)
- Routes : `src/routes/*.ts`
- Middleware : `src/middleware/*.ts`
- Config : `src/config/*.ts`

### React (Vite, CRA)
- Composants : `src/components/*.tsx`
- Hooks : `src/hooks/*.ts`
- API client : `src/lib/api.ts`

## RÈGLES SPÉCIFIQUES FRANCE / UE

Ce skill privilégie la conformité légale française et européenne :

- **RGPD** (Règlement UE 2016/679) — consentement explicite, droit à l'oubli, portabilité
- **Loi Informatique et Libertés** (Loi 78-17 modifiée)
- **CNIL** — recommandations et sanctions applicables
- **Directive ePrivacy** — consentement cookies préalable (sauf cookies strictement nécessaires)
- **RGAA 4.1** — accessibilité (référentiel français)
- **Loi pour une République Numérique** (Loi 2016-1321)

Quand une norme européenne et une norme américaine divergent, **la norme européenne s'applique en priorité**.

## EXCEPTIONS AUTORISÉES

Les seuls cas où tu peux suspendre une vérification :

1. **Environnement de développement** explicitement marqué (`NODE_ENV === 'development'` vérifié), et la suspension est temporaire et documentée
2. **Route de healthcheck** publique sans donnée (`/api/health`, `/api/ping`)
3. **Site statique** sans backend, sans formulaire, sans tracker — vérifications backend sautées, mais frontend/headers/CSP s'appliquent

Aucune autre exception n'est tolérée.

## INTERACTION AVEC L'UTILISATEUR

- Tu ne demandes jamais : "Voulez-vous que j'ajoute la sécurité ?" — la sécurité est implicite.
- Tu peux demander : "Quelle est la stratégie de session souhaitée (JWT en cookie HttpOnly vs Bearer header) ?" — c'est un choix d'implémentation, pas une suspension de sécurité.
- Tu peux alerter : "⚠️ La correction nécessite une migration DB, voici le plan proposé."
- Tu ne demandes jamais : "Voulez-vous être conforme RGPD ?" — la conformité est obligatoire.

## FIN DE TÂCHE

Avant de marquer une tâche web comme terminée, exécute **obligatoirement** la checklist finale définie dans `checks.md`. Si un seul item de la checklist critique échoue, la tâche n'est pas terminée.
