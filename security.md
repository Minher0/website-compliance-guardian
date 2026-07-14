# SECURITY — Référentiel de sécurité appliqué

Ce fichier est la source de vérité pour toutes les vérifications de sécurité. Il doit être appliqué à chaque génération de code web, sans exception.

## 1. OWASP TOP 10 — Vérifications obligatoires

### A01 — Broken Access Control

**Règle :** Chaque endpoint sensible doit vérifier l'identité ET l'autorisation.

```typescript
// ❌ INTERDIT — endpoint sensible sans auth
export async function GET(request: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}

// ✅ OBLIGATOIRE
import { getSession } from '@/lib/auth';
import { requireRole } from '@/lib/rbac';

export async function GET(request: Request) {
  const session = await getSession();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  requireRole(session, ['admin']);
  const users = await db.user.findMany({ select: { id: true, email: true } });
  return Response.json(users);
}
```

**Vérifications automatiques à appliquer :**
- Toute route `app/api/**/route.ts` ou `pages/api/**.ts` doit appeler un guard d'auth (`getSession`, `requireUser`, `requireRole`) si elle expose une donnée non-publique.
- Vérifier l'appartenance de la ressource (`if (resource.userId !== session.userId`) — ne pas se fier à l'ID passé dans l'URL.
- Toujours préférer deny-by-default : autoriser explicitement les actions, jamais interdire les exceptions.

### A02 — Cryptographic Failures

**Règles :**
- Mots de passe : `bcrypt` (cost ≥ 12) ou `argon2id` (recommandé). Jamais MD5/SHA1/SHA256 simple.
- Tokens JWT : algorithme `HS256` avec secret ≥ 256 bits, ou `RS256` avec paire de clés. Jamais `none`.
- Données sensibles au repos : chiffrer avec `crypto.scrypt` ou une librairie auditée (`node-jose`).
- En transit : TLS 1.2 minimum, TLS 1.3 recommandé. Jamais HTTP pour une donnée perso.
- Secrets en clair dans le code : INTERDIT. Utiliser `process.env` + `.env.local` (jamais committé).

```typescript
// ❌ INTERDIT
const API_KEY = 'sk_live_1234567890';
const jwt = sign(payload, 'secret');

// ✅ OBLIGATOIRE
const API_KEY = process.env.STRIPE_API_KEY!;
const jwt = sign(payload, process.env.JWT_SECRET!, { algorithm: 'HS256', expiresIn: '15m' });
```

### A03 — Injection

**Règle :** Aucune entrée utilisateur ne doit être concaténée dans une requête SQL, commande shell, ou template HTML non échappé.

```typescript
// ❌ INTERDIT
const result = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
exec(`ls ${userInput}`);
const html = `<div>${userName}</div>`; // si userName vient d'un user

// ✅ OBLIGATOIRE
const result = await db.user.findFirst({ where: { email } }); // Prisma paramétré
execFile('ls', [safePath]); // pas de shell
const html = `<div>${escapeHtml(userName)}</div>`; // ou React échappe par défaut
```

### A04 — Insecure Design

**Règle :** Toute fonctionnalité sensible doit avoir un modèle de menace implicite :
- Limite de tentatives (lockout après 5 échecs sur login)
- Validation côté serveur systématique (le client est hostile)
- Logs de sécurité (échecs auth, accès refusés, modifications sensibles)
- Idempotence des mutations financières

### A05 — Security Misconfiguration

**Règles :**
- Headers de sécurité activés (voir section 7)
- `NODE_ENV=production` en prod
- Stack traces désactivées en prod (`next.config.js` → `productionBrowserSourceMaps: false`)
- Pas de routes debug exposées (`/api/debug`, `/api/admin/health` détaillé)
- CORS configuré explicitement, jamais `Access-Control-Allow-Origin: *` avec credentials

### A06 — Vulnerable & Outdated Components

**Règle :** Avant d'ajouter une dépendance, vérifier :
- `npm audit` après install
- Pas de version avec advisory connu
- Préférer les dépendances maintenues (commit < 12 mois)
- Lockfile commité (`package-lock.json` ou `pnpm-lock.yaml`)

### A07 — Identification & Authentication Failures

**Règles :**
- Mot de passe : ≥ 12 caractères, vérification contre liste de mots de passe compromis (optionnel via `haveibeenpwned` API)
- Session : cookie HttpOnly + Secure + SameSite=Lax ou Strict
- JWT : court (15 min access, 7 jours refresh), rotation du refresh
- Login : rate limit (5 tententes / minute / IP)
- Logout : invalidation serveur (pas juste suppression cookie)
- Reset password : token à usage unique, expiration 15 min, invalidation des sessions existantes

### A08 — Software & Data Integrity Failures

**Règles :**
- Pas de désérialisation de données non signées
- Subresource Integrity (SRI) sur les scripts externes : `<script src="..." integrity="sha384-...">`
- Vérifier les signatures des webhooks (Stripe, GitHub, etc.) avec le secret partagé
- Pas de `eval`, `Function()`, `vm.runInNewContext()` sur entrée utilisateur

### A09 — Security Logging & Monitoring Failures

**Règles — events à logger obligatoirement :**
- Échecs de login (avec IP, user agent, timestamp)
- Accès refusés (401, 403)
- Modifications sensibles (mot de passe, email, rôle)
- Création / suppression de comptes
- Échecs de validation de webhook
- Logs immuables (append-only), rétention ≥ 12 mois (RGPD)

```typescript
import { logger } from '@/lib/logger';

await logger.security('login_failed', {
  email: maskEmail(email),
  ip: request.headers.get('x-forwarded-for'),
  userAgent: request.headers.get('user-agent'),
});
```

### A10 — Server-Side Request Forgery (SSRF)

**Règles :**
- Toute URL venant de l'utilisateur et fetchée côté serveur doit être validée :
  - Schéma autorisé (http/https uniquement)
  - Host non-IP-privée (10.x, 192.168.x, 127.x, 169.254.x, ::1)
  - DNS rebinding : résoudre l'IP AVANT la requête, valider, puis fetch avec `fetch(url, { headers: { Host: ... } })`

```typescript
import { isPublicHostname } from '@/lib/ssrf-guard';

if (!isPublicHostname(url)) {
  return Response.json({ error: 'Forbidden host' }, { status: 400 });
}
```

## 2. COOKIES — Configuration sécurisée obligatoire

**Règle absolue :** Tout cookie doit avoir les 3 attributs suivants en production :
- `httpOnly: true` — inaccessible au JS client
- `secure: true` — HTTPS uniquement
- `sameSite: 'lax' | 'strict'` — protection CSRF

```typescript
// ✅ Configuration standard
const response = NextResponse.next();
response.cookies.set({
  name: 'session',
  value: token,
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  maxAge: 60 * 60 * 24 * 7, // 7 jours
});
```

**Exceptions autorisées :**
- Cookies de consentement (banner) — non HttpOnly car lus par le JS, mais `secure` + `sameSite=lax`
- Cookies tiers (analytics) — seulement APRÈS consentement RGPD, `secure` obligatoire

**Jamais autorisé :**
- Cookie d'auth/session sans `httpOnly`
- Cookie sans `secure` en production
- Cookie avec `sameSite: 'none'` sans `secure: true`

## 3. AUTH — Architecture recommandée

### Sessions (recommandé pour Next.js)

```typescript
// lib/auth.ts
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';

export async function createSession(userId: string) {
  const token = jwt.sign({ sub: userId }, process.env.JWT_SECRET!, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
  const refresh = jwt.sign({ sub: userId, type: 'refresh' }, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: '7d',
  });
  
  cookies().set('access_token', token, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 900,
  });
  cookies().set('refresh_token', refresh, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/api/auth/refresh', maxAge: 604800,
  });
}
```

### Middleware d'auth

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

const PUBLIC_ROUTES = ['/', '/login', '/register', '/api/health'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (PUBLIC_ROUTES.some(r => pathname.startsWith(r))) {
    return NextResponse.next();
  }
  
  const token = request.cookies.get('access_token')?.value;
  if (!token) return NextResponse.redirect(new URL('/login', request.url));
  
  try {
    await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET!));
    return NextResponse.next();
  } catch {
    return NextResponse.redirect(new URL('/api/auth/refresh', request.url));
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

## 4. CSRF — Protection obligatoire

**Règle :** Toute mutation (POST/PUT/PATCH/DELETE) issue d'un navigateur doit être protégée.

### Stratégie 1 — SameSite=Lax (recommandé par défaut)
Déjà couverte par la config cookie. Suffit pour la plupart des cas.

### Stratégie 2 — Double submit token (mutations sensibles)

```typescript
// lib/csrf.ts
import { cookies } from 'next/headers';
import { randomBytes } from 'crypto';

export function generateCsrfToken(): string {
  const token = randomBytes(32).toString('hex');
  cookies().set('csrf_token', token, {
    httpOnly: false, // doit être lisible côté client pour l'envoyer
    secure: true,
    sameSite: 'lax',
    path: '/',
  });
  return token;
}

export function verifyCsrfToken(token: string): boolean {
  const cookieToken = cookies().get('csrf_token')?.value;
  if (!cookieToken || !token) return false;
  // constant-time comparison
  return cookieToken.length === token.length && 
    crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(token));
}
```

### Stratégie 3 — Origin/Referer check (alternative)
Pour les API JSON, vérifier `Origin` ou `Referer` correspond au domaine attendu.

```typescript
const origin = request.headers.get('origin');
if (origin !== new URL(request.url).origin) {
  return Response.json({ error: 'CSRF detected' }, { status: 403 });
}
```

## 5. RATE LIMITING — Obligatoire sur endpoints sensibles

**Endpoints à protéger obligatoirement :**
- `/api/auth/login`
- `/api/auth/register`
- `/api/auth/reset-password`
- `/api/auth/verify-email`
- `/api/contact`
- `/api/newsletter/subscribe`
- `/api/search` (si coûteux)
- Tout endpoint de paiement

### Implémentation recommandée (Upstash Redis)

```typescript
// lib/rate-limit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const limiters = {
  auth: new Ratelimit({
    redis: Redis.fromEnv(),
    limiter: Ratelimit.slidingWindow(5, '1 m'),
    prefix: 'rl:auth',
  }),
  contact: new Ratelimit({
    redis: Redis.fromEnv(),
    limiter: Ratelimit.slidingWindow(3, '1 h'),
    prefix: 'rl:contact',
  }),
};

export async function rateLimit(
  identifier: string,
  type: keyof typeof limiters
): Promise<{ success: boolean }> {
  return limiters[type].limit(identifier);
}
```

### Fallback sans Redis (en mémoire, single-instance)

```typescript
// lib/rate-limit-memory.ts
const hits = new Map<string, { count: number; resetAt: number }>();

export function rateLimitMemory(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = hits.get(key);
  if (!entry || entry.resetAt < now) {
    hits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  entry.count++;
  return entry.count <= max;
}
```

### Application dans une route

```typescript
import { rateLimit } from '@/lib/rate-limit';

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ?? 'unknown';
  const { success } = await rateLimit(ip, 'auth');
  if (!success) {
    return Response.json({ error: 'Too many requests' }, { status: 429, headers: { 'Retry-After': '60' } });
  }
  // ... logique
}
```

## 6. PROTECTION DES ENDPOINTS SENSIBLES

**Endpoints considérés sensibles :**
- Auth (login, register, password reset, 2FA)
- Profil utilisateur (modification email, password)
- Paiement
- Administration
- Suppression de données (RGPD droit à l'oubli)
- Export de données (RGPD portabilité)

**Protections obligatoires :**
1. Authentification requise
2. Autorisation (rôle / propriété ressource)
3. Rate limit
4. CSRF (si mutation navigateur)
5. Validation stricte des entrées
6. Audit log
7. Re-authentification pour actions critiques (changement de password) — demander le mot de passe actuel

## 7. HEADERS HTTP DE SÉCURITÉ — Configuration Next.js

```typescript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // réduire 'unsafe-*' en prod
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self' https://api.example.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "upgrade-insecure-requests",
    ].join('; '),
  },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
```

**Vérifications automatiques :**
- Toute app Next.js doit avoir ce bloc headers dans `next.config.js`
- CSP doit inclure `frame-ancestors 'none'` ou `DENY` X-Frame-Options
- HSTS doit avoir `includeSubDomains` et `preload` en prod
- `Permissions-Policy` doit désactiver les APIs non utilisées

## 8. VALIDATION CRYPTO — constant-time comparison

Pour toute comparaison de token, hash, secret : utiliser `crypto.timingSafeEqual`, jamais `===`.

```typescript
// ❌ INTERDIT — timing attack
if (userToken === expectedToken) { ... }

// ✅ OBLIGATOIRE
import { timingSafeEqual } from 'crypto';
const a = Buffer.from(userToken);
const b = Buffer.from(expectedToken);
if (a.length === b.length && timingSafeEqual(a, b)) { ... }
```

## 9. LOGS — ce qui ne doit JAMAIS apparaître

- Mots de passe (même partiels)
- Tokens complets (JWT, API keys, refresh tokens)
- Numéros de carte bancaire (seuls les 4 derniers digits, et jamais le CVV)
- Données de santé
- Données de géolocalisation précise
- Cookies de session

```typescript
// ✅ Bon
logger.info('login', { userId, ip: maskIp(ip) });

// ❌ Mal
logger.info('login', { userId, token, password: 'ilovecats' });
```

## 10. ENVIRONNEMENT — Variables obligatoires

Toute application web doit définir (au minimum) :

```bash
# .env.example (commité)
NODE_ENV=production
JWT_SECRET=            # ≥ 32 chars, généré avec `openssl rand -hex 32`
JWT_REFRESH_SECRET=    # ≥ 32 chars, différent de JWT_SECRET
DATABASE_URL=          # postgres://user:pass@host:port/db
ENCRYPTION_KEY=        # 32 bytes hex, pour chiffrer données sensibles au repos
NEXTAUTH_URL=          # https://votre-domaine.com
UPSTASH_REDIS_REST_URL=
UPSTASH_REDIS_REST_TOKEN=
SENTRY_DSN=            # pour monitoring erreurs
```

Le fichier `.env.local` (avec valeurs réelles) doit être dans `.gitignore`.

## 11. COOKIE PREFIXES — `__Host-` et `__Secure-`

Voir `advanced.md` §3 pour le détail. **Règle :** tout cookie sensible en production doit utiliser `__Host-` (sauf nécessité de partage cross-sous-domaine).

```typescript
cookies().set('__Host-session', token, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
  // ❌ pas de `domain` avec __Host-
});
```

## 12. MFA / 2FA — Voir `advanced.md` §2

Pour toute application manipulant des données sensibles (paiement, santé, admin), la MFA est obligatoire. Pattern TOTP + backup codes + rate limit OTP (5/5min) + re-authentification avant désactivation.

## 13. MASS ASSIGNMENT — Protection Prisma

```typescript
// ❌ INTERDIT
await db.user.update({ where: { id }, data: body });

// ✅ Toujours whitelist via Zod
const UpdateSchema = z.object({ name: z.string().optional(), email: z.string().email().optional() });
await db.user.update({ where: { id }, data: UpdateSchema.parse(body) });
```

## 14. REDOS — Regex DoS

Voir `advanced.md` §5. Règle : éviter `(X+)+`, `(X*)*`, limiter la longueur de l'input avant validation, préférer Zod ou `re2`.

## 15. RACE CONDITIONS — TOCTOU

Voir `advanced.md` §4. Pour toute mutation avec check-then-update (stock, coupon, solde) : utiliser `updateMany` avec condition dans `where`, ou transaction avec `SELECT FOR UPDATE`. Idempotence via `Idempotency-Key` pour mutations externes.

## 16. NEXT_PUBLIC_ LEAK — Voir `advanced.md` §20

Aucune variable `NEXT_PUBLIC_*` ne doit contenir un secret. Le prefix `NEXT_PUBLIC_` inline la valeur dans le bundle JS client. Vérifier avec `rg "NEXT_PUBLIC_"` et `grep -r "sk_live\|password\|secret" .next/static/chunks/`.

## 17. PIÈGES SPÉCIFIQUES AU SERVERLESS — Vercel, Netlify, Cloudflare Workers, Deno Deploy

Les fonctions serverless ont des contraintes uniques qui invalident plusieurs patterns "qui semblent sécurisés". Cette section est **obligatoire** dès que le projet utilise une de ces plateformes.

### 17.1 Rate limiting en mémoire = INUTILE

```typescript
// ❌ INUTILE sur Vercel — se réinitialise à chaque cold start
const buckets = new Map<string, { count: number; resetAt: number }>();

export function rateLimitMemory(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = buckets.get(key);
  if (!entry || entry.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  entry.count++;
  return entry.count <= max;
}
```

**Pourquoi ça ne marche pas :**
- Vercel cold start après quelques minutes d'inactivité
- Chaque cold start = nouvelle instance = `Map` vide
- Un attaquant patient (1 req / 5 min) contourne totalement
- Même en hot, plusieurs instances isolées ne partagent pas la Map

**Solution :** Utiliser un stockage persistant externe.

```typescript
// ✅ Upstash Redis (recommandé pour Vercel — HTTP, pas de connexion persistante)
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export const rateLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'),
  prefix: 'rl:login',
  analytics: true,
});

// ✅ Alternative : Vercel KV (built-in)
import { kv } from '@vercel/kv';

// ✅ Alternative : Neon DB (Postgres) — si pas de Redis
import { db } from '@/lib/db';
// Table LoginAttempt (ip, count, lockedUntil) — voir examples.md EXEMPLE 23
```

### 17.2 Rate limit basé sur cookie = contournable

```typescript
// ❌ CONTOURNABLE — l'attaquant supprime le cookie
export async function rateLimitByCookie(request: Request) {
  const cookie = request.cookies.get('rate_limit');
  // ...
}
```

**Solution :** Baser sur l'IP via le header `x-forwarded-for` (Vercel) ou `cf-connecting-ip` (Cloudflare).

```typescript
// ✅ Basé sur l'IP — non contournable par clearing cookie
function getClientIp(request: Request): string {
  // Vercel: x-forwarded-for
  // Cloudflare: cf-connecting-ip
  // Netlify: x-nf-client-connection-ip
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-nf-client-connection-ip') ??
    'unknown'
  );
}
```

### 17.3 Sessions en mémoire = perdues

```typescript
// ❌ PERDUES à chaque cold start
const sessions = new Map<string, { userId: string; expiresAt: Date }>();
```

**Solution :** Sessions en DB, ou JWT stateless (pas de stockage serveur).

```typescript
// ✅ Option 1 : Sessions en DB (Neon, Supabase)
await db.session.create({
  data: { id: sessionId, userId, expiresAt: new Date(Date.now() + 900_000) },
});

// ✅ Option 2 : JWT stateless (recommandé pour serverless)
const token = jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: '15m' });
// Pas de stockage serveur → pas de cold start issue
// Inconvénient : pas de révocation immédiate, sauf si on stocke une blacklist
```

### 17.4 Files uploadés en `public/` = servis publiquement

Sur Vercel, tout fichier dans `public/` est servi directement, sans possibilité de vérifier l'auth.

```typescript
// ❌ DANGEREUX — n'importe qui peut accéder à /uploads/evil.svg
await fs.writeFile(`./public/uploads/${filename}`, buffer);
```

**Solution :** Stocker dans un bucket S3/R2 privé, ou dans un dossier non-servi avec une route API qui vérifie l'auth avant de servir le fichier.

```typescript
// ✅ Option 1 : S3/R2 privé + URL signée
const url = await getSignedUrl(s3, new GetObjectCommand({ /* ... */ }), { expiresIn: 3600 });

// ✅ Option 2 : Route API qui vérifie l'auth avant de servir
// app/api/files/[id]/route.ts
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  
  const file = await db.file.findUnique({ where: { id: params.id } });
  if (!file || file.userId !== session.userId) {
    return Response.json({ error: 'Not found' }, { status: 404 });
  }
  
  return new Response(file.content, {
    headers: { 'Content-Type': file.mimeType },
  });
}
```

### 17.5 Timeout des fonctions serverless

Vercel Hobby : 10s max par fonction. Vercel Pro : 60s. Cloudflare Workers : 30s (CPU time).

**Implications :**
- Opérations longues (génération PDF, envoi d'emails batch) → utiliser une queue (Inngest, Trigger.dev, SQS)
- bcrypt cost 12 prend ~300ms → OK, mais ne pas paralléliser sur plusieurs logins
- Upload de gros fichiers → streamer vers S3 directement depuis le client (presigned URL)

### 17.6 Edge Middleware — Vérification JWT en Edge runtime

Le middleware Next.js tourne en Edge runtime, qui ne supporte pas `jsonwebtoken` (utilise `NodeJS` crypto). Utiliser `jose`.

```typescript
// ❌ NE FONCTIONNE PAS en Edge runtime
import jwt from 'jsonwebtoken';
const payload = jwt.verify(token, process.env.JWT_SECRET!);

// ✅ jose fonctionne en Edge runtime
import { jwtVerify } from 'jose';
const { payload } = await jwtVerify(
  token,
  new TextEncoder().encode(process.env.JWT_SECRET!)
);
```

### 17.7 Variables d'environnement par environnement

Vercel différencie Development / Preview / Production. Une variable `NEXT_PUBLIC_API_URL` peut avoir des valeurs différentes.

**Vérification :**
- Toutes les variables critiques définies en Production
- Preview environnement protégé (Vercel Protection Password) si secrets présents
- Pas de secrets dans Development (utiliser des valeurs factices)

### 17.8 Logs serverless éphémères

Les `console.log` disparaissent avec l'instance. Pour audit RGPD (art. 30, 32), utiliser un service de logs persistant.

```typescript
// ❌ Logs éphémères
console.log('login_failed', { email, ip });

// ✅ Logs persistants (Sentry, Axiom, Logflare, Datadog)
import * as Sentry from '@sentry/nextjs';
Sentry.captureMessage('login_failed', {
  level: 'warning',
  tags: { ip: maskIp(ip) },
  extra: { email: maskEmail(email) },
});
```

## 18. BRUTE-FORCE PROTECTION — Lockout progressif et persistant

La protection brute-force ne se limite pas à un rate limit simple. Elle doit être **progressive** (escalade des temps de lockout) et **persistante** (survit aux cold starts et au clearing des cookies).

### Schedule de lockout progressif

| Tentatives échouées | Durée du lockout |
|---|---|
| 3 | 30 secondes |
| 5 | 1 minute |
| 7 | 5 minutes |
| 10 | 15 minutes |
| 15 | 1 heure |
| 20 | 24 heures |
| 25+ | Permanent (levée manuelle DB uniquement) |

### Règles critiques

1. **Compteur stocké en DB** (Prisma, Postgres) ou Redis — **JAMAIS en mémoire**
2. **Basé sur l'IP** (`x-forwarded-for` sur Vercel) — **JAMAIS sur un cookie client**
3. **Survit aux cold starts serverless** (donc DB ou Redis, pas Map)
4. **Ne peut PAS être contourné par :**
   - Clearing les cookies du navigateur
   - Redémarrant le navigateur
   - Changeant de user-agent
   - Utilisant un incognito mode
5. **Après un lockout expiré**, le compteur n'est **PAS remis à 0** — l'échec suivant doit escalader (ex: après un lockout de 5 min, le 8e échec → 15 min, pas retour à 30s)
6. **Sur login réussi**, le compteur est remis à 0
7. **L'UI affiche le temps restant** avant retry (countdown)
8. **Le header HTTP `Retry-After`** est renvoyé avec le status 429
9. **Les messages d'erreur ne leakent PAS** le nombre exact de tentatives (sauf pour avertir l'utilisateur légitime : "Trop de tentatives. Réessayez dans 5 minutes.")

### Implémentation complète — Voir `examples.md` EXEMPLE 23

Le pattern complet (Prisma schema + logique de lockout + route API + UI) est documenté dans `examples.md` EXEMPLE 23. Réutiliser ce code pour toute route `/api/auth/login`.
