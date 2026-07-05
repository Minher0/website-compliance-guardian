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
- [ ] Login rate-limité (5 tentatives/min/IP)
- [ ] Lockout après 5 échecs (15 min)
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

### Rate limiting
- [ ] `/api/auth/login` rate-limité
- [ ] `/api/auth/register` rate-limité
- [ ] `/api/auth/reset-password` rate-limité
- [ ] `/api/contact` rate-limité
- [ ] `/api/newsletter/subscribe` rate-limité
- [ ] Tout endpoint public sensible rate-limité

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

À inclure dans la réponse de fin de tâche :

```
🔒 Compliance Guardian — Vérification finale

✅ CRITIQUE
- [✓] Aucun secret en clair
- [✓] Toutes les routes API sensibles authentifiées
- [✓] Cookies : HttpOnly + Secure + SameSite
- [✓] Validation Zod sur tous les inputs
- [✓] CSP et headers de sécurité configurés
- [✓] Bannière cookies RGPD
- [✓] Page /privacy et /legal

⚠️ ÉLEVÉ
- [✓] Rate limiting sur /api/auth/*
- [✓] CSRF sur mutations
- [✓] Routes client correspondent à routes serveur
- [⚠️] Tests unitaires : 60% coverage, cible 80%

ℹ️ FAIBLE
- [ℹ️] RGAA : 3 éléments à contraste AA à corriger
- [ℹ️] README à compléter avec variables d'env

STATUT : LIVRABLE avec réserves mineures
```
