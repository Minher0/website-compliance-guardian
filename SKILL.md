---
name: website-compliance-guardian
description: Couche de sécurité et conformité OBLIGATOIRE pour toute génération ou modification de code web. S'active automatiquement. Vérifie OWASP Top 10, RGPD, brute-force PROGRESSIF et PERSISTANT, pièges serverless (Vercel/Netlify/Cloudflare Workers), faux positifs courants, qualité (pas seulement présence). Priorité à la correction automatique.
activation: always-on
scope: web
priority: critical
languages: [typescript, javascript, tsx, jsx, node]
frameworks: [nextjs, react, node, express, fastify]
jurisdiction: [FR, EU]
serverless: [vercel, netlify, cloudflare-workers, deno-deploy]
---

# WEBSITE-COMPLIANCE-GUARDIAN

## ⚠️ RÈGLE D'OR — OBLIGATOIRE ET NON-CONTOURNABLE

**AVANT de retourner TOUT code web à l'utilisateur, tu DOIS obligatoirement :**

1. **Ouvrir `checks.md`** et exécuter mentalement les vérifications critiques (section 🚨)
2. **Pour chaque "oui"** (présence d'une protection), vérifier la **QUALITÉ** en consultant le fichier de référence approprié — PAS seulement la présence
3. **Consulter `false-positives.md`** pour vérifier que tu n'es pas en train de valider un anti-pattern
4. **Consulter `security.md` section "Pièges serverless"** si le projet utilise Vercel, Netlify, Cloudflare Workers, ou toute fonction serverless
5. **Ajouter la section `🔒 Compliance Guardian`** à la fin de ta réponse — cette section est **OBLIGATOIRE**, même si vide ("OK, aucune correction requise")

**Cette étape n'est PAS optionnelle.** Si tu ne le fais pas, tu laisses passer des failles critiques qui ressemblent à des sécurités mais n'en sont pas (rate limit en mémoire sur Vercel = 0 protection réelle, etc.).

### Marqueur de fin obligatoire

Ta réponse ne peut **JAMAIS** se terminer sans la section `🔒 Compliance Guardian`. Si tu oublies cette section, considère que la tâche est incomplète.

Format attendu (même si aucune correction n'a été nécessaire) :

```
🔒 Compliance Guardian — <résumé>

[CRITIQUE] <fichier>:<ligne> — <problème>
  → Correction : <action>
  → Référence : OWASP A0X / RGPD Art. X / Piège serverless / Faux positif

[ÉLEVÉE] <fichier>:<ligne> — <problème>
  → Correction : <action>

— ou, si tout est OK —

🔒 Compliance Guardian — OK, aucune correction requise.
  Vérifications exécutées : 20 dimensions + faux positifs + pièges serverless
```

## PRINCIPE FONDAMENTAL — QUALITÉ PAS PRÉSENCE

Le skill ne valide JAMAIS une protection sur la base de sa seule présence. Pour chaque sécurité attendue, vérifier :

| Demande | Réponse insuffisante (PRÉSENCE) | Réponse attendue (QUALITÉ) |
|---|---|---|
| "Y a-t-il un rate limit sur /login ?" | "Oui, il y a `Map<ip, count>`" | "Oui, persistant en DB/Redis, basé sur IP, avec lockout progressif" |
| "Y a-t-il auth sur /admin ?" | "Oui, `GET /api/admin/settings` check la session" | "Oui, mais attention : si /admin/settings est publique pour vérifier l'auth côté client, c'est une faille — créer /api/admin/me dédiée" |
| "Le cookie est-il sécurisé ?" | "Oui, httpOnly: true" | "Oui, httpOnly + secure + sameSite=lax + prefix `__Host-` + pas de maxAge pour session admin" |
| "Le password est-il vérifié ?" | "Oui, `if (input === password)`" | "Non — utiliser `timingSafeEqual` (timing attack). Hash bcrypt/argon2." |
| "L'upload est-il validé ?" | "Oui, check du Content-Type" | "Non — vérifier magic bytes + nom UUID + SVG interdit + sharp EXIF" |
| "Les secrets sont-ils protégés ?" | "Oui, `.env*` dans .gitignore" | "Oui, mais `.env.example` est aussi exclu → ajouter `!.env.example`" |

**Règle absolue :** Quand tu hésites entre "présence" et "qualité", vérifie TOUJOURS la qualité. Quand un pattern semble sécurisé mais correspond à une entrée de `false-positives.md`, corrige-le.

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
11. **Toute mention de Vercel, Netlify, Cloudflare Workers, Deno Deploy, Edge Functions** → activer les vérifications "Pièges serverless"
12. **Toute route `/api/auth/*`, `/api/admin/*`, `/api/login`, `/api/register`** → activer la vérification brute-force progressif + persistant

## COMPORTEMENT OBLIGATOIRE

### 1. Vérification systématique avant chaque réponse contenant du code web

Avant de retourner tout code web à l'utilisateur, exécute **en silence** les 20 vérifications. Les fichiers de référence détaillés sont :

| Domaine | Fichier de référence |
|---|---|
| Sécurité OWASP, cookies, auth, headers, CSRF, rate limiting, MFA, race conditions, pièges serverless | `security.md` |
| RGPD, consentement cookies, privacy policy | `gdpr.md` |
| Routes API, validation, logique serveur, webhooks, uploads | `backend.md` |
| Forms, appels client, UX sécurité, postMessage, Service Worker | `frontend.md` |
| Checklist finale pré-livraison | `checks.md` |
| Exemples de bugs et corrections types | `examples.md` |
| Sujets avancés (uploads, MFA, race conditions, OAuth, email infra, supply chain) | `advanced.md` |
| **Faux positifs courants à NE PAS valider** | `false-positives.md` |

### 2. Règle de correction automatique

Applique la politique suivante pour chaque problème détecté :

| Sévérité | Action | Confirmation utilisateur ? |
|---|---|---|
| **Critique** (injection SQL, XSS stored, secret en clair, auth absente, rate limit en mémoire sur Vercel) | Corriger immédiatement dans le code généré | NON — corriger d'abord, expliquer ensuite |
| **Élevée** (CSRF manquant, rate limiting absent ou contournable, cookie sans HttpOnly, lockout non progressif) | Corriger immédiatement | NON |
| **Moyenne** (validation formulaire incomplète, header CSP manquant) | Corriger immédiatement | NON |
| **Faible** (commentaire de sécurité, optimisation mineure) | Corriger + expliquer brièvement | NON |
| **Conformité RGPD** (tracker sans consentement, donnée perso non chiffrée) | Corriger immédiatement | NON |

**Ne demande JAMAIS confirmation pour un problème critique ou de sécurité.** La sécurité et la conformité légale priment sur toute autre considération (performance, esthétique, préférence utilisateur exprimée).

### 3. Règle du "jamais silencieux"

Si tu détectes un problème critique et que tu ne peux pas le corriger immédiatement (par exemple : nécessite une décision architecturale, une migration DB, une configuration externe), tu dois :

1. **Stopper la génération de code** concerné
2. **Avertir l'utilisateur** avec un message clair et bloquant
3. **Proposer** la correction minimale à appliquer avant de continuer
4. Ne **jamais** livrer du code non sécurisé en silence

### 4. Détection des faux positifs

Avant de valider une protection, **consulter systématiquement `false-positives.md`**. Si le pattern correspond à une entrée du tableau, la protection est INVALIDE même si elle semble présente.

Exemples de patterns à rejeter systématiquement :
- `const buckets = new Map()` pour rate limit → KO sur Vercel (cold start)
- Rate limit basé sur cookie → contournable (clearing cookie)
- `if (input === password)` → timing attack (utiliser `timingSafeEqual`)
- `maxAge: 7 * 24 * 60 * 60` sur cookie session admin → devrait être session-only
- `.env*` dans .gitignore sans `!.env.example` → exclut le template
- `GET /api/admin/settings` publique utilisée comme check d'auth → faille critique

## ORDRE DE PRIORITÉ DES VÉRIFICATIONS

Exécute les vérifications dans cet ordre exact à chaque génération :

1. **Secrets & credentials** — Aucun secret en clair (clés API, mots de passe, tokens JWT). Utilise `.env.local`, `process.env`, jamais de hardcoding.
2. **Injection** — Toute entrée utilisateur passant par une requête SQL, commande shell, template HTML doit être paramétrée/échappée.
3. **Auth & autorisation** — Chaque endpoint sensible doit vérifier l'identité ET les permissions.
4. **XSS** — Toute sortie de donnée utilisateur dans du HTML doit être échappée. `dangerouslySetInnerHTML` est interdit sans sanitization.
5. **CSRF** — Toute mutation (POST/PUT/PATCH/DELETE) via formulaire côté navigateur doit avoir un token CSRF ou utiliser `SameSite=Strict/Lax`.
6. **Cookies** — `HttpOnly`, `Secure`, `SameSite` obligatoires. Prefix `__Host-` recommandé. Pas de `maxAge` sur cookie de session admin.
7. **Headers HTTP** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
8. **Rate limiting + brute-force protection** — Tout endpoint public sensible (login, register, password reset) doit avoir un rate limit **persistant en DB/Redis** (PAS en mémoire), basé sur l'IP, avec **lockout progressif** (3→30s, 5→1min, 7→5min, 10→15min, 15→1h, 20→24h, 25+→permanent). Voir `security.md` §17 (Pièges serverless) et `checks.md` "Brute-force protection".
9. **Validation** — Tout input (body, query, params, headers) doit être validé par un schéma (Zod, Yup, Joi) côté serveur.
10. **RGPD** — Tout tracker, cookie non essentiel, collecte de donnée perso nécessite consentement explicite. CNIL compatible.
11. **Routes appelées côté client** — Toute URL appelée par `fetch`/`axios` doit correspondre à une route réellement définie côté serveur. Vérifie l'existence du fichier de route.
12. **Dépendances** — Aucune `eval`, `Function()`, `child_process.exec` avec entrée utilisateur. Vérifie les vulnérabilités connues (`npm audit`).
13. **Navigation légale cohérente** — Sitemap, footer et pages légales (`/privacy`, `/legal`, `/cookies`) doivent rester synchronisés.
14. **File upload security** — Magic bytes (pas seulement `Content-Type`), nom UUID (pas `file.name` direct), SVG interdit ou sanitizer, stockage hors `public/`, EXIF stripping via `sharp`, rate limit. Voir `advanced.md` §1.
15. **Race conditions** — Toute mutation avec check-then-update (coupon, stock, solde) doit être atomique.
16. **Information disclosure** — Messages neutres (pas d'énumération d'utilisateurs), `X-Powered-By` supprimé, source maps désactivées en prod, stack traces jamais dans les réponses.
17. **Cookie prefixes & cache** — `__Host-`, `Cache-Control: no-store` sur pages authentifiées, `Vary: Cookie`.
18. **NEXT_PUBLIC_ leak** — Aucune variable `NEXT_PUBLIC_*` ne doit contenir un secret.
19. **Cross-origin** — `postMessage` (origin whitelist + Zod), WebSocket (Origin check + auth), iframe (`sandbox` minimal).
20. **Order injection & pagination DoS** — Paramètre `sort` whitelisté, `limit` plafonné côté serveur, cursor-based pagination sur grandes tables.

**Après ces 20 vérifications, exécuter OBLIGATOIREMENT :**
- Vérification des faux positifs (consulter `false-positives.md`)
- Vérification des pièges serverless (consulter `security.md` §17) si applicable

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

### Serverless (Vercel, Netlify, Cloudflare Workers, Deno Deploy)
- ⚠️ **Pièges spécifiques** — Voir `security.md` §17 obligatoirement
- Pas de state en mémoire (cold start)
- Pas de rate limit en mémoire
- Pas de sessions en mémoire
- Stockage uploads en bucket privé (pas `public/`)

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

Avant de marquer une tâche web comme terminée, exécute **obligatoirement** la checklist finale définie dans `checks.md`. Si un seul item de la checklist critique échoue, la tâche n'est pas terminée. La section `🔒 Compliance Guardian` doit être présente dans la réponse finale.
