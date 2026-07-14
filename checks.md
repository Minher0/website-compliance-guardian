# CHECKS — Checklist pré-livraison obligatoire

Cette checklist doit être exécutée **avant de marquer toute tâche de génération web comme terminée**. Chaque item critique (🚨) qui échoue bloque la livraison. Les items élevés (⚠️) doivent être corrigés avant livraison. Les items faibles (ℹ️) peuvent être reportés mais doivent être signalés.

## 🚨 CRITIQUE — Bloque la livraison

### Secrets & credentials
- [ ] Aucun secret en clair dans le code (clés API, mots de passe, JWT secrets)
- [ ] Tous les secrets via `process.env` + `.env.local` non commité
- [ ] `.env.example` commité avec placeholders
- [ ] `.gitignore` contient `.env`, `.env.local`, `.env.production`
- [ ] Aucun secret dans l'historique git (vérifier avec `git log -p | rg -i 'password|secret|key|token'`)

### Authentification & autorisation
- [ ] Toute route `app/api/**/route.ts` sensible appelle `auth()` ou `getSession()`
- [ ] Toute mutation vérifie l'appartenance de la ressource (`resource.userId === session.userId`) ou le rôle
- [ ] Login rate-limité ET **PERSISTANT en base de données** (PAS en mémoire — les fonctions serverless Vercel se réinitialisent à chaque cold start)
- [ ] Rate limit **basé sur l'IP** (`x-forwarded-for` sur Vercel) — PAS sur un cookie (clearing les cookies ne doit PAS contourner la protection)
- [ ] **Lockout PROGRESSIF** (smartphone-style) :
  - 3 failed → 30 sec
  - 5 failed → 1 min
  - 7 failed → 5 min
  - 10 failed → 15 min
  - 15 failed → 1 hour
  - 20 failed → 24 hours
  - 25+ → permanent (manuel DB)
- [ ] Le compteur d'échecs est **PERSISTANT** (DB, Redis, ou Upstash — PAS en mémoire)
- [ ] Après un lockout expiré, le compteur n'est **PAS remis à 0** (l'échec suivant doit escalader, pas recommencer à 0)
- [ ] Sur login réussi, le compteur est remis à 0
- [ ] L'utilisateur voit le temps restant (countdown dans l'UI)
- [ ] Header HTTP `Retry-After` renvoyé avec le status 429
- [ ] Les messages d'erreur ne leakent pas le nombre exact de tentatives (sauf pour avertir l'utilisateur légitime)
- [ ] Logout invalide la session serveur (pas juste le cookie)
- [ ] Reset password : token à usage unique, expiration ≤ 15 min, invalidation des sessions existantes
- [ ] Mots de passe : `bcrypt` cost ≥ 12 ou `argon2id`
- [ ] JWT : algorithme `HS256`/`RS256`, jamais `none`, secret ≥ 256 bits

### Cookies
- [ ] Cookie de session : `httpOnly: true`
- [ ] Cookie de session : `secure: true` en production
- [ ] Cookie de session : `sameSite: 'lax'` ou `'strict'`
- [ ] Aucun cookie sensible sans `httpOnly`
- [ ] Cookie CSRF (si utilisé) : `secure: true`, `sameSite: 'lax'`
- [ ] Aucun cookie avec `sameSite: 'none'` sans `secure: true`

### Injection & XSS
- [ ] Toutes les requêtes DB sont paramétrées (pas de string interpolation)
- [ ] Pas de `$queryRaw` avec entrée utilisateur sans `Prisma.sql` template tag
- [ ] Pas de `exec()` / `execSync()` avec entrée utilisateur (utiliser `execFile`)
- [ ] Pas de `eval`, `Function()`, `vm.runInNewContext()` sur entrée utilisateur
- [ ] Pas de `dangerouslySetInnerHTML` sans `DOMPurify.sanitize()`
- [ ] Pas d'URL utilisateur dans `href` sans validation de schéma (`http`, `https`, `mailto`, `tel`)

### Validation
- [ ] Tout body de requête validé par Zod (ou Yup/Joi)
- [ ] Tout query param validé
- [ ] Tout param dynamique de route validé (type, format)
- [ ] Validation côté serveur présente même si validation client existe

### CSRF
- [ ] Toute mutation (POST/PUT/PATCH/DELETE) via formulaire a protection CSRF
- [ ] Token CSRF vérifié en constant-time
- [ ] Cookie de session en `SameSite=Lax` ou `Strict` (protection CSRF minimale)

### Headers HTTP
- [ ] `Content-Security-Policy` configuré dans `next.config.js`
- [ ] `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- [ ] `X-Frame-Options: DENY` ou CSP `frame-ancestors 'none'`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy` désactive les APIs non utilisées

### RGPD — Consentement
- [ ] Bannière cookies présente si cookies non essentiels
- [ ] Bouton "Refuser" aussi visible que "Accepter"
- [ ] Aucune case pré-cochée dans la bannière
- [ ] Scripts de tracking (GA, Meta, etc.) chargés conditionnellement au consentement
- [ ] Page `/privacy` existe et est complète
- [ ] Page `/legal` existe
- [ ] Page `/cookies` (ou gestion dans le footer) existe
- [ ] Lien "Gérer mes cookies" accessible dans le footer
- [ ] Consentement tracé (preuve en BDD)

### Navigation légale cohérente — Triplet sitemap / footer / pages
- [ ] Chaque page légale (`/privacy`, `/legal`, `/cookies`, `/cgu`) existe physiquement (fichier `app/<page>/page.tsx`)
- [ ] Chaque page légale est référencée dans le footer (lien persistant sur toutes les pages)
- [ ] Chaque page légale est listée dans `sitemap.xml` (ou route `app/sitemap.ts`)
- [ ] Les URLs du footer correspondent exactement aux URLs du sitemap (pas de `/mentions-legales` vs `/legal`)
- [ ] Pas d'ancre `/#mentions-legales` comme lien légal — page dédiée obligatoire
- [ ] Chaque page légale a une URL canonique `<link rel="canonical">` stable
- [ ] `robots.txt` n'exclut pas les pages légales (doivent être indexées)
- [ ] Si ajout/retrait d'une page légale, le sitemap ET le footer sont mis à jour dans le même commit

### RGPD — Droits
- [ ] Bouton "Supprimer mon compte" accessible (droit à l'oubli)
- [ ] Bouton "Exporter mes données" accessible (portabilité)
- [ ] Édition de profil (rectification)
- [ ] Désinscription newsletter en 1 clic (article L. 34-5 du Code des postes)

### Données sensibles
- [ ] Donnée sensible (santé, biométrie, etc.) — non collectée sans AIPD
- [ ] Donnée perso chiffrée au repos si critique (numéros, identifiants)
- [ ] Aucune donnée bancaire stockée (déléguer à Stripe/PCI-DSS)
- [ ] Logs ne contiennent pas de données sensibles

## ⚠️ ÉLEVÉ — Corriger avant livraison

### Rate limiting — QUALITÉ requise (pas seulement présence)
- [ ] `/api/auth/login` rate-limité ET persistant (DB/Redis, PAS en mémoire)
- [ ] `/api/auth/register` rate-limité
- [ ] `/api/auth/reset-password` rate-limité
- [ ] `/api/contact` rate-limité
- [ ] `/api/newsletter/subscribe` rate-limité
- [ ] Tout endpoint public sensible rate-limité
- [ ] ⚠️ **Faux positif #1** : pas de `const buckets = new Map()` pour le rate limit (cold start serverless)
- [ ] ⚠️ **Faux positif #2** : rate limit basé sur l'IP, PAS sur un cookie client
- [ ] Rate limit utilise Upstash Redis / Vercel KV / Neon DB / Supabase (persistant)
- [ ] Si en mémoire, il s'agit d'un environnement non-serverless (long-running Node.js)

### Brute-force protection — PROGRESSIVE + PERSISTANT
- [ ] Compteur d'échecs stocké en **DB** (PAS en mémoire)
- [ ] Basé sur l'**IP** (header `x-forwarded-for` sur Vercel)
- [ ] **Lockout progressif** (voir schedule dans `security.md` §18)
  - 3 / 5 / 7 / 10 / 15 / 20 / 25+ échecs → 30s / 1min / 5min / 15min / 1h / 24h / permanent
- [ ] Le lockout **survit aux cold starts serverless** (DB ou Redis)
- [ ] Le lockout **ne peut PAS être contourné** en :
  - Clearing les cookies du navigateur
  - Redémarrant le navigateur
  - Changeant de user-agent
- [ ] Seul un login réussi OU l'expiration du lockout remet le compteur à 0 (ou partiellement)
- [ ] L'UI affiche le temps restant avant retry (countdown)
- [ ] Le header HTTP `Retry-After` est renvoyé avec le status 429
- [ ] Les messages d'erreur ne leakent pas le nombre exact de tentatives

### Serverless pitfalls — Voir `security.md` §17
- [ ] ⚠️ Pas de state en mémoire (`Map`, `WeakMap`, variable globale) pour sessions, rate limits, ou compteurs
- [ ] ⚠️ Sessions stockées en DB ou via JWT stateless (pas de `Map<sessionId, userId>`)
- [ ] ⚠️ Files uploadés en bucket privé (S3/R2) ou via route API auth — PAS dans `public/`
- [ ] ⚠️ Logs persistants (Sentry/Axiom/Datadog) — `console.log` disparaît avec l'instance
- [ ] Edge Middleware utilise `jose` (pas `jsonwebtoken`) pour vérifier les JWT
- [ ] Variables d'environnement définies en Production Vercel (pas juste Preview)
- [ ] Preview Vercel protégé par mot de passe si secrets présents
- [ ] Opérations longues (>10s) utilisent une queue (Inngest, Trigger.dev, SQS)

### Endpoints sensibles
- [ ] Changement de password exige le password actuel
- [ ] Changement d'email exige vérification (email de confirmation)
- [ ] Suppression de compte exige re-authentification
- [ ] Webhooks vérifient la signature (Stripe, GitHub, etc.)
- [ ] Cron endpoints vérifient `CRON_SECRET`

### Routes appelées côté client
- [ ] Toute URL `/api/...` appelée par `fetch`/`axios` correspond à une route serveur existante
- [ ] Méthode HTTP attendue correspond à la méthode exportée par la route
- [ ] Schéma de réponse validé (Zod) si source non fiable
- [ ] Pas d'URL absolue `https://...` sans proxy/whitelist

### Logs & monitoring
- [ ] Échecs de login loggés (IP, user agent, timestamp, email masqué)
- [ ] Accès refusés (401, 403) loggés
- [ ] Modifications sensibles loggées (audit trail)
- [ ] Logs ne contiennent ni password, ni token, ni carte, ni secret
- [ ] Sentry (ou équivalent) configuré en production

### Dépendances
- [ ] `npm audit` sans vulnérabilité critique
- [ ] Lockfile commité
- [ ] Pas de `// @ts-ignore` sur code critique
- [ ] Pas de `eslint-disable` sur règle de sécurité sans commentaire justificatif

### Performance & UX
- [ ] Bouton de soumission désactivé pendant l'envoi (anti-double-submit)
- [ ] Loading state visible pendant requêtes longues
- [ ] Messages d'erreur génériques (pas de fuite d'info)
- [ ] Confirmation avant action destructrice
- [ ] Liens externes en `rel="noopener noreferrer"`

### File upload security — Voir `advanced.md` §1
- [ ] Magic bytes vérifiés (pas seulement `Content-Type`)
- [ ] Nom de fichier généré (UUID, pas `file.name` direct)
- [ ] Extension validée via whitelist
- [ ] SVG interdit ou sanitizer (DOMPurify + CSP `default-src 'none'`)
- [ ] Taille limitée (`Content-Length` check + limite 5 Mo photos)
- [ ] Stockage hors `public/` (bucket S3 privé ou dossier non servi)
- [ ] Images re-encodées avec `sharp` (strip EXIF GPS)
- [ ] Rate limiting sur endpoint d'upload

### MFA / 2FA — Voir `advanced.md` §2
- [ ] TOTP setup avec secret chiffré en BDD
- [ ] Backup codes générés (10), hashés en BDD, à usage unique
- [ ] Rate limit OTP (5 tentatives / 5 min)
- [ ] Re-authentification (password + MFA) pour désactiver MFA
- [ ] Notification email quand MFA activée/désactivée
- [ ] Login flow : challenge MFA séparé, pas de session créée avant validation
- [ ] SMS 2FA évité (préférer TOTP)

### Information disclosure — Voir `advanced.md` §15
- [ ] Inscription : message neutre (ne révèle pas si email existe)
- [ ] Reset password : message neutre
- [ ] Login : message identique "identifiants invalides"
- [ ] `X-Powered-By` header supprimé (`poweredByHeader: false`)
- [ ] Source maps désactivées en prod (`productionBrowserSourceMaps: false`)
- [ ] Stack traces jamais dans les réponses API (uniquement en logs internes)
- [ ] `.git/` non accessible publiquement (vérifier `curl /.git/HEAD`)
- [ ] Pas d'erreur 404 révélant des routes internes

### Race conditions — Voir `advanced.md` §4
- [ ] Coupons / promotions : `updateMany` atomique avec condition dans `where`
- [ ] Stock / inventaire : transaction avec `SELECT FOR UPDATE`
- [ ] Retraits / transferts de solde : transaction + check dans la même TX
- [ ] Idempotence : header `Idempotency-Key` pour mutations externes (paiement, email)
- [ ] Contraintes `UNIQUE` en BDD pour éviter doublons (cartCoupon, etc.)
- [ ] Tests de charge avec requêtes parallèles sur mutations sensibles

### Cookie prefixes & cache security — Voir `advanced.md` §3, §16
- [ ] Cookie de session préfixé `__Host-` (ou `__Secure-` si cross-sous-domaine)
- [ ] Pages authentifiées : `Cache-Control: no-store, no-cache, must-revalidate, private`
- [ ] `Vary: Cookie` sur réponses personnalisées
- [ ] Logout : headers `Cache-Control: no-store` + invalidation session serveur

### Order injection & pagination DoS — Voir `backend.md` §14, §15
- [ ] Paramètre `sort` validé via whitelist de colonnes
- [ ] Paramètre `order` validé (`asc` | `desc`)
- [ ] Paramètre `limit` plafonné côté serveur (max 100)
- [ ] Paramètre `page` plafonné (max 1000)
- [ ] Préférer cursor-based pagination sur grandes tables

### Cross-origin (postMessage, WebSocket, iframe) — Voir `frontend.md` §11, `advanced.md` §10
- [ ] `postMessage` receive : `event.origin` validé via whitelist
- [ ] `postMessage` send : `targetOrigin` explicite (jamais `*`)
- [ ] WebSocket : `Origin` vérifié sur handshake
- [ ] WebSocket : auth sur handshake (cookie ou token)
- [ ] WebSocket : rate limit par socket
- [ ] iframes tierces : `sandbox` minimal (pas `allow-all`)
- [ ] iframes tierces : SRI sur scripts chargés

### Supply chain & build — Voir `advanced.md` §18, §19
- [ ] `npm audit --audit-level=high` en CI
- [ ] Lockfile commité
- [ ] Branche `main` protégée (pas de push direct, PR obligatoire)
- [ ] Reviews obligatoires (min 1, idéalement 2)
- [ ] Status checks CI obligatoires avant merge
- [ ] Dockerfile : user non-root (pas de `USER root`)
- [ ] Dépendabot / Renovate activé
- [ ] SRI (`integrity`) sur tous les scripts CDN tiers

### RGPD avancé — Voir `gdpr.md` §15-19
- [ ] Pas de cookie wall (contenu accessible sans consentement)
- [ ] DPA signé avec chaque sous-traitant (hébergeur, email, analytics)
- [ ] Registre des traitements (Article 30) à jour
- [ ] Analytics : Matomo/Plausible sans cookie OU GA avec consentement
- [ ] Pas de cross-device tracking sans consentement explicite séparé

## ℹ️ FAIBLE — À corriger si temps

### Accessibilité (RGAA 4.1)
- [ ] Tous les champs ont un `<label>` associé
- [ ] Toutes les images ont un `alt` descriptif (ou `alt=""` pour décoratives)
- [ ] Contraste AA (4.5:1 normal, 3:1 gros texte)
- [ ] Navigation clavier complète (tabindex logique, focus visible)
- [ ] `aria-*` corrects sur composants interactifs
- [ ] HTML sémantique (`<nav>`, `<main>`, `<article>`, `<section>`)

### Documentation
- [ ] README documente l'installation, les variables d'env, le déploiement
- [ ] Code commenté pour les fonctions complexes
- [ ] Types JSDoc sur les fonctions publiques
- [ ] Schéma de BDD documenté

### Tests
- [ ] Tests unitaires sur fonctions critiques (auth, validation, paiement)
- [ ] Tests d'intégration sur les routes sensibles
- [ ] Tests E2E sur les parcours critiques (login, register, checkout)

### Performance
- [ ] LCP < 2.5s
- [ ] FID < 100ms
- [ ] CLS < 0.1
- [ ] Bundle JS < 200 KB (initial)
- [ ] Images optimisées (`next/image`, WebP, lazy loading)

## 🔄 VÉRIFICATIONS AUTOMATISÉS RECOMMANDÉES

### À installer dans le projet

```json
// package.json
{
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "lint:security": "eslint --ext .ts,.tsx --config .eslintrc.security.js",
    "typecheck": "tsc --noEmit",
    "test": "vitest"
  },
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^7.0.0",
    "eslint-plugin-security": "^2.0.0",
    "eslint-plugin-no-secrets": "^0.8.9",
    "eslint-plugin-zod": "^0.2.0"
  }
}
```

### ESLint rules de sécurité

```js
// .eslintrc.security.js
module.exports = {
  plugins: ['security', 'no-secrets'],
  rules: {
    'security/detect-object-injection': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-child-process': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-pseudoRandomBytes': 'error',
    'security/detect-new-buffer': 'error',
    'no-secrets/no-secrets': 'error',
  },
};
```

### CI — Workflow GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npm audit --audit-level=high
      - run: npm run lint:security
      - run: npm run typecheck
      - run: npx @rehrenreich/secret-scan
      - uses: github/codeql-action/init@v3
        with: { languages: javascript-typescript }
      - uses: github/codeql-action/analyze@v3
```

## 📋 TEMPLATE DE RAPPORT DE VÉRIFICATION

À inclure dans la réponse de fin de tâche — **OBLIGATOIRE** (même si aucune correction) :

```
🔒 Compliance Guardian — Vérification finale

✅ CRITIQUE
- [✓] Aucun secret en clair
- [✓] Toutes les routes API sensibles authentifiées
- [✓] Cookies : HttpOnly + Secure + SameSite + __Host- prefix
- [✓] Validation Zod sur tous les inputs
- [✓] CSP et headers de sécurité configurés
- [✓] Bannière cookies RGPD
- [✓] Page /privacy et /legal

⚠️ ÉLEVÉ
- [✓] Rate limiting PERSISTANT (DB/Redis, pas mémoire) sur /api/auth/*
- [✓] Brute-force protection PROGRESSIVE (3→30s, 5→1min, ..., 25+→permanent)
- [✓] Rate limit basé sur l'IP (pas cookie)
- [✓] CSRF sur mutations
- [✓] Routes client correspondent à routes serveur
- [⚠️] Tests unitaires : 60% coverage, cible 80%

🛡️ SERVERLESS (si Vercel/Netlify/CF Workers)
- [✓] Pas de state en mémoire pour sessions/rate limits
- [✓] Files uploadés hors public/ (bucket privé)
- [✓] Edge Middleware utilise jose (pas jsonwebtoken)
- [✓] Logs persistants (Sentry/Axiom)

❌ FAUX POSITIFS — Patterns invalides rejetés
- [✓] Pas de `const buckets = new Map()` pour rate limit
- [✓] Pas de rate limit basé sur cookie
- [✓] Pas de `if (input === password)` (timingSafeEqual)
- [✓] Pas de `maxAge` sur cookie session admin
- [✓] `.env.example` autorisé dans .gitignore
- [✓] Pas de `GET /api/admin/settings` publique pour check auth

ℹ️ FAIBLE
- [ℹ️] RGAA : 3 éléments à contraste AA à corriger
- [ℹ️] README à compléter avec variables d'env

STATUT : LIVRABLE avec réserves mineures
```

**Rappel :** La section `🔒 Compliance Guardian` est **OBLIGATOIRE** dans toute réponse contenant du code web. Sans elle, la tâche est considérée incomplète.
