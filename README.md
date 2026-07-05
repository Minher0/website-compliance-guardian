# website-compliance-guardian

> Couche de sécurité et conformité automatique pour toute génération ou modification de code web (Next.js, React, Node.js, API, sites statiques). Fonctionne en mode **always-on** : aucune commande utilisateur n'est requise pour l'activer.

![license](https://img.shields.io/badge/license-MIT-blue)
![jurisdiction](https://img.shields.io/badge/jurisdiction-FR%20%2F%20EU-success)
![status](https://img.shields.io/badge/status-stable-brightgreen)

## 🎯 Objectif

Ce Claude Code Skill agit comme une **couche invisible de protection** qui s'intègre à chaque génération de code web. Il ne demande jamais à l'utilisateur s'il faut sécuriser — il sécurise. Il ne demande jamais s'il faut être conforme RGPD — il est conforme.

Il intervient en continu pendant la génération de code, vérifie 13 dimensions de sécurité/conformité, et corrige automatiquement les problèmes détectés.

## ✨ Caractéristiques

- **Always-on** : s'active automatiquement sur toute tâche de génération web
- **Correction automatique** : ne demande jamais confirmation pour un problème critique
- **Conformité FR/UE** : RGPD, Loi Informatique et Libertés, CNIL, ePrivacy
- **Multi-stack** : Next.js (App + Pages Router), React, Node.js (Express, Fastify)
- **Référentiel OWASP Top 10** intégré
- **13 dimensions de vérification** par génération de code (incluant la cohérence sitemap / footer / pages légales)

## 📋 Vérifications effectuées

À chaque génération ou modification de code web, le skill vérifie automatiquement :

1. **Sécurité OWASP Top 10** — injection, XSS, broken access control, etc.
2. **RGPD / conformité légale** — cookies, consentement, données personnelles
3. **Routes API et cohérence du backend** — existence, signatures, autorisations
4. **Validation des formulaires** — Zod côté client ET serveur
5. **Protection des endpoints sensibles** — auth, autorisation, rate limiting
6. **Configuration sécurisée des cookies** — HttpOnly, Secure, SameSite
7. **Rate limiting** sur toutes les routes publiques sensibles
8. **Protection CSRF** sur les mutations navigateur
9. **Headers de sécurité HTTP** — CSP, HSTS, X-Frame-Options, etc.
10. **Existence réelle des routes appelées côté client** — cohérence fetch ↔ route serveur
11. **Secrets & credentials** — aucun en clair, variables d'env obligatoires
12. **Dépendances** — pas de `eval`, `Function()`, audit `npm`
13. **Navigation légale cohérente** — triplet sitemap / footer / pages légales synchronisé, URLs canoniques stables

## 📁 Structure du skill

```
website-compliance-guardian/
├── SKILL.md          # Règles principales, comportement global, mode always-on
├── security.md       # OWASP Top 10, cookies, auth, headers, CSRF, rate limiting
├── gdpr.md           # RGPD, consentement cookies, privacy policy, droits des personnes
├── backend.md        # Routes API, validation, logique serveur, webhooks, cron
├── frontend.md       # Forms, appels client, XSS, UX sécurité, accessibilité
├── checks.md         # Checklist pré-livraison (critique / élevé / faible)
└── examples.md       # 16 exemples de bugs + corrections automatiques
```

## 🚀 Installation

### Pour Claude Code (CLI Anthropic)

1. **Cloner le dépôt dans votre dossier de skills Claude Code :**

```bash
git clone https://github.com/Minher0/website-compliance-guardian.git ~/.claude/skills/website-compliance-guardian
```

2. **Ou copier les fichiers manuellement** dans `~/.claude/skills/website-compliance-guardian/`

3. Le skill s'active automatiquement dès qu'une tâche implique du code web — aucune configuration supplémentaire n'est requise.

### Pour usage manuel

Vous pouvez également consulter les fichiers markdown comme référentiel de revue de code, ou les intégrer dans vos prompts système personnalisés.

## 🔧 Utilisation

Le skill n'a pas d'interface utilisateur. Il s'active silencieusement et ajoute une section `🔒 Compliance Guardian` à la fin de chaque réponse contenant du code web, listant les corrections appliquées.

### Exemple de comportement

**Vous demandez :**
> Crée une route API Next.js pour la connexion utilisateur

**Le skill applique automatiquement :**
- Validation Zod sur le body (email, password)
- Rate limiting (5 tentatives / minute / IP)
- Vérification bcrypt du mot de passe
- Génération JWT avec secret ≥ 32 caractères
- Cookie de session `httpOnly: true, secure: true, sameSite: 'lax'`
- Log de sécurité (échec / succès)
- Message d'erreur générique (pas de fuite d'info)
- Headers de réponse appropriés

Aucune de ces décisions n'est demandée — elles sont appliquées.

## 🇫🇷 Conformité France / Union Européenne

Ce skill privilégie la conformité légale française et européenne :

| Référence | Couverture |
|---|---|
| **RGPD** (Règlement UE 2016/679) | Consentement, droit à l'oubli, portabilité, 72h notification |
| **Loi Informatique et Libertés** (78-17) | Déclarations CNIL, droits d'accès |
| **Directive ePrivacy** | Consentement cookies préalable |
| **Loi pour une République Numérique** (2016-1321) | Mentions légales obligatoires |
| **RGAA 4.1** | Accessibilité (référentiel français) |
| **CNIL** | Recommandations et sanctions applicables |

Quand une norme européenne et une norme américaine divergent, **la norme européenne s'applique en priorité**.

## 📊 Stack supportée

| Stack | Routes API | Middleware | Config |
|---|---|---|---|
| **Next.js App Router** | `app/api/[route]/route.ts` | `middleware.ts` | `next.config.js` |
| **Next.js Pages Router** | `pages/api/[route].ts` | `pages/_middleware.ts` | `next.config.js` |
| **Node.js Express** | `src/routes/*.ts` | `src/middleware/*.ts` | `src/config/*.ts` |
| **Node.js Fastify** | `src/routes/*.ts` | `src/plugins/*.ts` | `src/config/*.ts` |
| **React (Vite/CRA)** | — | — | `vite.config.ts` |

## 📚 Exemples de corrections automatiques

Le fichier [`examples.md`](./examples.md) contient 16 exemples détaillés de bugs courants et leur correction automatique :

1. Secret API en clair dans le code
2. Injection SQL via template string
3. XSS via `dangerouslySetInnerHTML`
4. Cookie de session non sécurisé
5. IDOR (Insecure Direct Object Reference)
6. Route API appelée côté client inexistante
7. Tracker chargé sans consentement RGPD
8. Endpoint admin exposé sans auth
9. Webhook Stripe sans vérification de signature
10. Formulaire sans validation serveur
11. Open Redirect
12. Pas de page `/privacy`
13. Headers HTTP de sécurité manquants
14. JWT secret faible
15. Modification de password sans re-authentification
16. Sitemap et footer désynchronisés des pages légales

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour proposer une amélioration :

1. Fork le dépôt
2. Créer une branche `feature/ma-feature`
3. Commit avec message conventionnel (`feat:`, `fix:`, `docs:`)
4. Ouvrir une Pull Request

### Ajouter un exemple de bug

Modifiez `examples.md` en respectant le format :

```markdown
## EXEMPLE N — <titre>

### ❌ Bug détecté
<code du bug>

### ✅ Correction automatique
<code corrigé>

**Explication :** ...
**Référence :** OWASP A0X / RGPD Art. X
```

## 📄 Licence

MIT — voir [`LICENSE`](./LICENSE).

## ⚠️ Avertissement

Ce skill est une aide à la conformité et à la sécurité. Il ne remplace pas :
- Une audit de sécurité réalisé par un professionnel (pentest)
- Une analyse d'impact RGPD (AIPD) pour les traitements à risque
- Une consultation juridique pour les cas spécifiques
- La déclaration CNIL si votre traitement l'exige

Pour les traitements sensibles (données de santé, biométrie, enfants, profilage à grande échelle), consultez un DPO et réalisez une AIPD.

## 🔗 Références

- [RGPD — Texte consolidé](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [CNIL — Guide RGPD](https://www.cnil.fr/fr/rgpd-de-quoi-parle-t-on)
- [CNIL — Recommandations cookies](https://www.cnil.fr/fr/cookies-et-autres-traceurs)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [RGAA 4.1](https://www.numerique.gouv.fr/publications/rgaa-accessibilite/)
- [Loi pour une République Numérique](https://www.economie.gouv.fr/republique-numerique)

---

**Made with 🛡️ for a safer and more compliant web.**
