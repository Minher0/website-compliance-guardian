# FALSE-POSITIVES — Patterns à NE PAS valider

Ce fichier liste les patterns qui **semblent sécurisés** mais qui ne le sont pas en réalité. À consulter **systématiquement** avant de valider une protection.

## Tableau des faux positifs

| # | Pattern détecté | Semble OK car… | Problème réel | Correction attendue |
|---|---|---|---|---|
| 1 | `const buckets = new Map()` pour rate limit | "Il y a un rate limit" | Se réinitialise à chaque cold start serverless (Vercel, Netlify, CF Workers) | Utiliser Upstash Redis, Vercel KV, Neon DB, ou session DB |
| 2 | Rate limit basé sur un cookie client | "Il y a un rate limit" | L'attaquant supprime le cookie et recommence à zéro | Baser sur l'IP (`x-forwarded-for`) |
| 3 | Cookie `maxAge: 7 * 24 * 60 * 60` pour session admin | "Cookie httpOnly + secure présent" | Session admin doit être session-only (pas de maxAge) | Retirer le `maxAge`, ou utiliser refresh token |
| 4 | `if (input === password)` ou `if (token === expectedToken)` | "Auth présente" | Vulnérable aux timing attacks (`===` sort au premier octet différent) | `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` |
| 5 | Upload avec `Content-Type` check seul | "Upload validé" | `Content-Type` envoyé par le client, contournable en modifiant le header | Vérifier magic bytes (octets du fichier) |
| 6 | `.env*` dans `.gitignore` sans `!.env.example` | "Secrets protégés" | Exclut aussi `.env.example` qui devrait être commité | Ajouter `!.env.example` |
| 7 | `GET /api/admin/settings` publique pour vérifier l'auth côté client | "Route présente, check session" | Si publique pour check, faille critique : leak de settings si non auth | Créer `/api/admin/me` dédiée qui retourne `{ authenticated: bool }` |
| 8 | `localStorage.setItem('token', jwt)` | "Auth côté client" | XSS peut lire le localStorage et voler le token | JWT en cookie httpOnly + secure |
| 9 | `password: z.string().min(8)` | "Validation présente" | 8 caractères est insuffisant en 2026 (GPU brute-force) | `min(12)` + complexité (majuscule, chiffre, spécial) |
| 10 | `eval(userInput)` "contrôlé" | "Input validé" | Même validé, `eval` permet l'exécution arbitraire si l'input change | Jamais `eval` sur entrée utilisateur |
| 11 | CORS `Access-Control-Allow-Origin: *` avec `credentials: true` | "CORS configuré" | Combo interdit par les navigateurs, mais si contourné = fuite | Spécifier l'origine explicite, jamais `*` avec credentials |
| 12 | `dangerouslySetInnerHTML={{ __html: content }}` où `content` vient d'un CMS "de confiance" | "Source interne" | Si le CMS est compromis ou si un éditeur injecte `<script>`, XSS | `DOMPurify.sanitize(content)` même pour contenu interne |
| 13 | JWT sans `expiresIn` | "Token signé" | Token valide à vie → si volé, compromise permanente | `expiresIn: '15m'` (access) + refresh token séparé |
| 14 | `bcrypt.hash(password, 10)` | "Password hashé" | Cost 10 est devenu trop faible (GPU 2026) | Cost ≥ 12, ou préférer `argon2id` |
| 15 | `db.user.findUnique({ where: { id } })` sans select | "Requête paramétrée" | Prisma retourne tous les champs dont `passwordHash` | `select: { id, email, name }` explicite |
| 16 | Rate limit à 5 tentatives mais `maxAge` du compteur = 1 minute | "Rate limit présent" | Attaquant patient fait 5 tentatives / minute indéfiniment | Lockout progressif + compteur persistant |
| 17 | `if (request.method === 'POST')` sans vérifier `Origin` | "Méthode vérifiée" | CSRF : un site tiers peut soumettre un formulaire POST | Vérifier `Origin`/`Referer` OU token CSRF OU `SameSite` cookie |
| 18 | `process.env.JWT_SECRET = 'mysecret123'` | "Variable d'env utilisée" | Secret trop court (< 32 chars), brute-force possible | `openssl rand -hex 32` (64 chars hex) |
| 19 | `crypto.randomBytes(16)` pour tokens | "Token aléatoire" | 16 bytes = 128 bits, OK mais trop court pour sessions longues | 32 bytes (256 bits) pour sessions, 16 OK pour CSRF |
| 20 | `try { ... } catch (e) { return Response.json({ error: e.message }) }` | "Gestion d'erreur" | Stack trace et messages internes leakés au client | Logger en interne, retourner `'internal_error'` générique |
| 21 | `fetch(\`/api/users/${id}\`)` côté client avec `id` venant de l'URL | "Appel API typique" | Si `id` est `..%2F..%2Fadmin`, path traversal potentiel | Valider `id` (UUID pattern) avant l'appel |
| 22 | `headers: { 'Content-Type': 'application/json' }` sans `credentials` | "Fetch standard" | Cookies de session non envoyés → auth casse en prod | `credentials: 'same-origin'` (ou `'include'` si cross-domain) |
| 23 | `await User.findOne({ where: { email } })` puis retourne 404 si absent | "Gestion d'erreur propre" | User enumeration : attaquant teste 1000 emails | Message neutre "Si ce compte existe, un email a été envoyé" |
| 24 | `localStorage.setItem('user', JSON.stringify({...}))` | "State persisté" | Données perso en clair dans le navigateur (RGPD : minimisation) | Ne pas stocker de données perso en localStorage |
| 25 | `res.setHeader('X-Frame-Options', 'SAMEORIGIN')` mais pas de CSP | "Clickjacking protégé" | `X-Frame-Options` est déprécié au profit de CSP `frame-ancestors` | Ajouter CSP avec `frame-ancestors 'self'` |
| 26 | `if (process.env.NODE_ENV !== 'production') { /* debug */ }` | "Debug conditionnel" | Si `NODE_ENV` mal configuré en prod, debug exposé | Fail-fast au démarrage si `NODE_ENV` manquant |
| 27 | `<input type="hidden" name="userId" value={session.userId} />` | "Champ caché sécurité" | Modifier le DOM via DevTools change le `userId` → IDOR | Toujours utiliser `session.userId` côté serveur, jamais côté client |
| 28 | `bcrypt.compare(password, hash)` dans un `Promise.all` parallèle | "Auth efficace" | bcrypt est volontairement lent ; parallèle = DoS CPU | Limiter la concurrence (queue, rate limit sur l'endpoint) |
| 29 | `JSON.parse(request.body)` sans try/catch | "Body parsé" | Body malformé = exception non gérée → 500 + stack trace | `try/catch` ou validation Zod qui gère les invalides |
| 30 | `Cookie: session=abc123` sans `__Host-` prefix | "Cookie signé" | Sans prefix, vulnérable à l'injection de cookie subdomain | `__Host-session` (navigateur refuse les cookies non sécurisés) |
| 31 | `if (user.role === 'admin')` côté client pour afficher boutons | "RBAC implémenté" | Le client est hostile — l'UI ne fait que masquer, pas protéger | Vérifier le rôle côté serveur sur chaque endpoint admin |
| 32 | `sitemap.xml` listant des pages qui n'existent pas (ou inverse) | "Sitemap présent" | SEO dégradé + Google flag comme 404s | Synchroniser sitemap ↔ pages physiques à chaque commit |
| 33 | `robots.txt: Disallow: /admin/` | "Section admin masquée" | `robots.txt` est public — indique aux attaquants qu'il y a une section `/admin/` | Ne pas `Disallow` les sections sensibles, les protéger par auth |
| 34 | `if (email.endsWith('@company.com')) { /* trust */ }` | "Whitelist domaine" | Attaquant peut spoof le `From` ou utiliser `user@company.com.attacker.com` | Vérifier le domaine après `@` exactement, jamais `endsWith` lâche |
| 35 | `crypto.createHash('sha256').update(password).digest('hex')` | "Password hashé" | SHA-256 est rapide → brute-force GPU possible | bcrypt/argon2 (slow hash + salt) |
| 36 | `req.headers['x-api-key'] === process.env.API_KEY` | "Auth par clé API" | Timing attack via `===` | `timingSafeEqual` |
| 37 | `setTimeout(() => invalidate(token), 86400000)` | "Expiration programmée" | Si le process redémarre (serverless), le timeout est perdu | Stocker `expiresAt` en DB et vérifier à chaque requête |
| 38 | `if (process.env.VERCEL_ENV === 'preview')` pour bypass auth | "Environnement preview" | Preview URLs sont publiques si non protégées | Protéger les previews avec un mot de passe Vercel |
| 39 | `Math.random()` pour générer tokens | "Token généré" | `Math.random()` n'est pas cryptographiquement sûr | `crypto.randomBytes(32).toString('hex')` |
| 40 | `JSON.stringify(user)` dans les logs | "Log utile" | Leak le password hash, l'email, etc. | Logger uniquement les IDs + champs explicitement safe |

## Comment utiliser ce fichier

### Pour l'agent (IA exécutant le skill)

1. **Avant de valider une protection**, scanner ce tableau mentalement
2. Si le pattern correspond → la protection est INVALIDE
3. Appliquer la correction attendue automatiquement
4. Mentionner dans la section `🔒 Compliance Guardian` que c'était un faux positif

### Pour l'utilisateur (compréhension des corrections)

Quand tu vois dans la section Compliance Guardian :

```
[CRITIQUE] lib/rate-limit.ts:5 — Rate limit en mémoire (Map)
  → Correction : Migration vers Upstash Redis
  → Référence : Faux positif #1 (false-positives.md)
```

Cela signifie : "Le pattern semblait sécurisé (il y avait un rate limit), mais en réalité il ne fonctionnait pas sur Vercel. Le skill l'a détecté et corrigé."

## Patterns émergents à surveiller

Ces patterns sont apparus récemment et ne sont pas encore dans le tableau ci-dessus, mais le skill doit les signaler :

### 41. Edge Middleware sans vérification d'auth pour les pages protégées

```typescript
// ❌ Le middleware vérifie juste que le cookie existe, pas qu'il est valide
export function middleware(request: NextRequest) {
  if (request.cookies.get('session')) {
    return NextResponse.next(); // ⚠️ N'importe quel cookie "session" passe
  }
  return NextResponse.redirect('/login');
}
```

**Correction :** Vérifier le JWT signature dans le middleware (via `jose` qui fonctionne en Edge runtime).

### 42. Server Actions sans re-authentification

```typescript
// ❌ Server action qui supprime le compte sans re-demander le password
'use server';
export async function deleteAccount(userId: string) {
  await db.user.delete({ where: { id: userId } }); // ⚠️ CSRF + pas de re-auth
}
```

**Correction :** Re-authentification obligatoire + CSRF token + vérification `session.userId === userId`.

### 43. Composants client qui importent un module serveur

```typescript
// ❌ 'use client' component qui importe directement un module avec secret
'use client';
import { stripe } from '@/lib/stripe'; // ⚠️ stripe contient la secret key
```

**Correction :** Isoler `lib/stripe.server.ts` (jamais importé côté client), et `lib/stripe-client.ts` avec la publishable key uniquement.
