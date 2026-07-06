# ADVANCED — Sujets de sécurité avancés

Ce fichier regroupe les vérifications avancées qui dépassent le OWASP Top 10 standard mais reviennent fréquemment dans les audits réels. À connaître et à appliquer dès que le contexte le nécessite.

## 1. SÉCURITÉ DES UPLOADS DE FICHIERS — Deep dive

La validation du `Content-Type` côté client est **trivial à contourner**. Un attaquant envoie un fichier `.jpg` avec un `Content-Type: image/jpeg` mais un payload PHP/JS à l'intérieur.

### 1.1 Validation des magic bytes (octets magiques)

Le seul moyen fiable de vérifier le type réel d'un fichier est de lire ses premiers octets.

```typescript
// lib/file-validation.ts
import { readFile } from 'fs/promises';

const MAGIC_BYTES: Record<string, { offset: number; bytes: number[] }> = {
  'image/jpeg': { offset: 0, bytes: [0xFF, 0xD8, 0xFF] },
  'image/png': { offset: 0, bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  'image/webp': { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46] }, // RIFF
  'image/gif': { offset: 0, bytes: [0x47, 0x49, 0x46, 0x38] }, // GIF8
  'application/pdf': { offset: 0, bytes: [0x25, 0x50, 0x44, 0x46] }, // %PDF
};

export async function detectRealMimeType(filePath: string): Promise<string | null> {
  const buffer = await readFile(filePath, { flag: 'r' });
  for (const [mimeType, sig] of Object.entries(MAGIC_BYTES)) {
    const matches = sig.bytes.every((byte, i) => buffer[sig.offset + i] === byte);
    if (matches) return mimeType;
  }
  return null;
}
```

### 1.2 Path traversal via le nom de fichier

```typescript
// ❌ INTERDIT — path traversal
const uploadPath = `./uploads/${file.name}`;
// Si file.name = "../../../../etc/passwd", on écrit hors du dossier prévu

// ✅ OBLIGATOIRE — générer un nom aléatoire
import { randomUUID } from 'crypto';
import path from 'path';

const safeName = `${randomUUID()}${path.extname(file.name).toLowerCase()}`;
// Bonus : valider l'extension
const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.webp'];
if (!ALLOWED_EXT.includes(path.extname(safeName))) {
  throw new Error('Extension non autorisée');
}
```

### 1.3 SVG XSS

Le SVG est un format XML qui peut contenir du JavaScript. **Interdire l'upload de SVG** si tu n'as pas besoin de vectoriels, OU les servir avec `Content-Type: image/svg+xml` + `Content-Security-Policy: default-src 'none'` + sanitizer le contenu.

```typescript
// ❌ INTERDIT — XSS si uploadé puis servi directement
if (file.type === 'image/svg+xml') {
  await saveFile(file); // un SVG avec <script> s'exécutera
}

// ✅ Soit interdire
if (file.type === 'image/svg+xml') {
  return Response.json({ error: 'SVG non autorisé' }, { status: 400 });
}

// ✅ Soit sanitizer + servir avec CSP stricte
import { sanitize } from 'isomorphic-dompurify';
const cleaned = sanitize(await file.text(), {
  USE_PROFILES: { svg: true, svgFilters: true },
  FORBID_TAGS: ['script', 'foreignObject'],
  FORBID_ATTR: ['onload', 'onerror', 'onclick'],
});
```

### 1.4 EXIF / métadonnées GPS

Les photos prises au téléphone contiennent souvent la géolocalisation. **Stripping obligatoire** pour les uploads utilisateurs.

```typescript
import sharp from 'sharp';

// Ré-encoder l'image supprime les métadonnées
await sharp(inputBuffer)
  .resize(1920, 1920, { fit: 'inside', withoutEnlargement: true })
  .jpeg({ quality: 85 })
  .toFile(outputPath);
// sharp ne conserve pas l'EXIF par défaut — c'est exactement ce qu'on veut
```

### 1.5 Stockage hors `public/`

Les fichiers uploadés par les utilisateurs ne doivent **jamais** être dans `public/uploads/` (servis directement sans contrôle d'accès). Utilise :
- Un bucket S3/R2 avec URLs signées (recommandé)
- Un dossier privé + une route API qui vérifie l'auth avant de servir le fichier

```typescript
// ❌ INTERDIT
fs.writeFileSync(`public/uploads/${safeName}`, buffer);

// ✅ OBLIGATOIRE — bucket privé + URL signée
import { S3Client, PutObjectCommand, getSignedUrl } from '@aws-sdk/client-s3';
import { s3 } from '@/lib/s3';

await s3.send(new PutObjectCommand({
  Bucket: process.env.S3_BUCKET!,
  Key: `uploads/${safeName}`,
  Body: buffer,
  ContentType: detectedMime,
}));

const url = await getSignedUrl(s3, new GetObjectCommand({
  Bucket: process.env.S3_BUCKET!,
  Key: `uploads/${safeName}`,
}), { expiresIn: 3600 });
```

### 1.6 Limits obligatoires

- **Taille max** : 5 Mo photo, 10 Mo PDF, vérifier `Content-Length` avant parsing
- **Nombre max** par utilisateur / par heure (rate limit sur endpoint d'upload)
- **Dimensions max** image (rejeter 50000x50000 qui peut DoS sharp)

## 2. MFA / 2FA — Implémentation correcte

### 2.1 TOTP (recommandé — Google Authenticator, Authy, 1Password)

```typescript
// lib/mfa.ts
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

export async function setupMFA(userId: string) {
  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(
    user.email,
    process.env.APP_NAME!,
    secret
  );
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  
  // Stocker secret chiffré, NON activé tant que pas vérifié
  await db.user.update({
    where: { id: userId },
    data: { mfaSecretPending: encrypt(secret), mfaEnabled: false },
  });
  
  return { qrDataUrl, secret }; // secret affiché pour saisie manuelle
}

export async function verifyMFA(userId: string, token: string): Promise<boolean> {
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user.mfaSecret) return false;
  
  // Rate limit : 5 tentatives / 5 min
  const { success } = await rateLimit(`mfa:${userId}`, 5, '5m');
  if (!success) throw new ApiError(429, 'rate_limited');
  
  return authenticator.verify({
    token: token.replace(/\s/g, ''),
    secret: decrypt(user.mfaSecret),
  });
}
```

### 2.2 Backup codes (one-time)

Générer 10 codes à usage unique, à stocker en BDD (hashés comme les passwords). L'utilisateur doit les conserver en lieu sûr.

```typescript
import { randomBytes } from 'crypto';

export async function generateBackupCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: 10 }, () => 
    randomBytes(5).toString('hex').toUpperCase().match(/.{1,5}/g)!.join('-')
  );
  
  // Hash comme des passwords — pas de stockage en clair
  const hashedCodes = await Promise.all(
    codes.map(c => bcrypt.hash(c, 12))
  );
  
  await db.backupCode.createMany({
    data: hashedCodes.map(hash => ({ userId, hash, used: false })),
  });
  
  return codes; // retournés UNE seule fois à l'utilisateur
}
```

### 2.3 Règles critiques MFA

- **Re-authentification** obligatoire avant de désactiver MFA (demander password actuel + code MFA)
- **Rate limit** strict sur tentative OTP (5 / 5 min, lockout 15 min après)
- **Notification email** quand MFA est activée/désactivée
- **Backup codes** à usage unique, invalidés après usage
- **SMS 2FA déconseillé** (SIM swap, coût, latence) — préférer TOTP
- **"Se souvenir de cet appareil 30 jours"** = cookie séparé, HttpOnly, Secure, signé

### 2.4 Login flow avec MFA

```typescript
// app/api/auth/login/route.ts
export async function POST(request: Request) {
  // ... validation + password check ...
  
  if (user.mfaEnabled) {
    // NE PAS créer de session — retourner un challenge MFA
    const challengeId = await createMFAChallenge(user.id); // expire 5 min
    return Response.json({ 
      status: 'mfa_required',
      challengeId,
    });
  }
  
  // Pas de MFA → session normale
  await createSession(user.id);
  return Response.json({ status: 'ok' });
}

// app/api/auth/login/mfa/route.ts
export async function POST(request: Request) {
  const { challengeId, token } = await request.json();
  const challenge = await getMFAChallenge(challengeId);
  if (!challenge || challenge.expiresAt < new Date()) {
    return Response.json({ error: 'Challenge expiré' }, { status: 400 });
  }
  
  if (!await verifyMFA(challenge.userId, token)) {
    return Response.json({ error: 'Code invalide' }, { status: 401 });
  }
  
  await deleteMFAChallenge(challengeId);
  await createSession(challenge.userId);
  return Response.json({ status: 'ok' });
}
```

## 3. COOKIE PREFIXES — `__Host-` et `__Secure-`

Ces prefixes activent des protections natives du navigateur, sans configuration supplémentaire.

### `__Host-` (le plus strict)

```typescript
// ✅ Cookie "Host-Only" — aucune shared-with-subdomain leak
cookies().set('__Host-session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',          // OBLIGATOIRE : '/'
  // ❌ PAS de `domain` — interdit avec __Host-
});
```

**Garanties du navigateur :**
- `Secure` obligatoire
- Pas de `Domain` (cookie host-only, pas envoyé aux sous-domaines)
- `Path=/` obligatoire
- Ignoré si la connexion n'est pas HTTPS

### `__Secure-`

```typescript
cookies().set('__Secure-csrf', csrfToken, {
  httpOnly: false,
  secure: true,
  sameSite: 'lax',
  path: '/',
});
```

Moins strict que `__Host-` (autorise `Domain`), mais force `Secure`.

**Règle :** Tout cookie sensible en production devrait utiliser `__Host-`. Exception : cookies qui doivent être partagés entre sous-domaines légitimes (ex: `__Secure-` pour `.example.com`).

## 4. RACE CONDITIONS — TOCTOU et double-spend

### 4.1 Pattern classique : double application de coupon

```typescript
// ❌ VULNÉRABLE — race condition
export async function POST(request: Request) {
  const { couponCode, cartId } = await request.json();
  
  const coupon = await db.coupon.findUnique({ where: { code: couponCode } });
  if (coupon.usedCount >= coupon.maxUses) {
    return Response.json({ error: 'Coupon épuisé' }, { status: 400 });
  }
  
  // ⚠️ ENTRE LE CHECK ET L'UPDATE — 2 requêtes peuvent passer
  await db.coupon.update({
    where: { id: coupon.id },
    data: { usedCount: { increment: 1 } },
  });
  
  return Response.json({ success: true });
}
```

```typescript
// ✅ ATOMIQUE — incrémentation conditionnelle
export async function POST(request: Request) {
  const { couponCode, cartId } = await request.json();
  
  try {
    // UPDATE ... WHERE usedCount < maxUses — atomique
    const result = await db.coupon.updateMany({
      where: { 
        code: couponCode,
        usedCount: { lt: db.coupon.fields.maxUses }, // ✅ check atomique
      },
      data: { usedCount: { increment: 1 } },
    });
    
    if (result.count === 0) {
      return Response.json({ error: 'Coupon épuisé ou invalide' }, { status: 400 });
    }
    
    return Response.json({ success: true });
  } catch (err) {
    // Unique constraint violation (déjà appliqué à ce panier)
    if (err.code === 'P2002') {
      return Response.json({ error: 'Coupon déjà appliqué' }, { status: 409 });
    }
    throw err;
  }
}
```

### 4.2 Race sur retrait de solde

```typescript
// ❌ VULNÉRABLE — 2 retraits simultanés peuvent passer
const balance = await getBalance(userId);
if (balance < amount) throw new Error('Solde insuffisant');
await withdraw(userId, amount);

// ✅ Transaction avec SELECT FOR UPDATE (Prisma raw)
await db.$transaction(async (tx) => {
  const [user] = await tx.$queryRaw`
    SELECT * FROM "User" WHERE id = ${userId} FOR UPDATE
  `;
  if (user.balance < amount) {
    throw new Error('Solde insuffisant');
  }
  await tx.user.update({
    where: { id: userId },
    data: { balance: { decrement: amount } },
  });
  await tx.transaction.create({ data: { userId, amount, type: 'withdrawal' } });
});
```

### 4.3 Idempotence

Pour toute mutation financière ou à effets de bord externe (email, webhook), utiliser un **idempotency key** envoyée par le client :

```typescript
const idempotencyKey = request.headers.get('Idempotency-Key');
if (!idempotencyKey) {
  return Response.json({ error: 'Idempotency-Key requis' }, { status: 400 });
}

// Table IdempotencyRecord (key, response, expiresAt)
const existing = await db.idempotencyRecord.findUnique({
  where: { key_userId: { key: idempotencyKey, userId: session.userId } },
});
if (existing) {
  return Response.json(existing.response); // retourne la réponse d'origine
}

// Sinon, traiter + stocker la réponse
```

## 5. REDOS — Regex Denial of Service

Certaines regex ont un backtracking catastrophique. Sur entrée utilisateur (avant regex), ça peut bloquer le thread Node.js.

### Patterns dangereux

```typescript
// ❌ DANGEREUX — backtracking exponentiel
const emailRegex = /^([a-zA-Z0-9_\.\-+])+@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$/;
// Sur "a".repeat(30) + "!" → bloqué ~30s

const phoneRegex = /^(\d+)+$/;
// Sur "1".repeat(30) + "a" → bloqué ~30s

// Règle : éviter (X+)+, (X*)*, (X|Y)+ imbriqué
```

### Mitigation

1. **Préférer Zod** (utilise des parsers sécurisés)
2. **Tester avec des entrées longues** (>1000 chars) avant validation
3. **Utiliser `safeRegex`** de `safe-regex2` ou `re2` (Google RE2, pas de backtracking)
4. **Limiter la longueur** de l'input AVANT la regex

```typescript
import { RE2 } from 're2';

// ✅ Safe — RE2 n'a pas de backtracking catastrophique
const emailRegex = new RE2('^[^@]+@[^@]+\\.[^@]+$');

// ✅ Limitation de longueur préventive
if (input.length > 254) return Response.json({ error: 'Trop long' }, { status: 400 });
if (!emailRegex.test(input)) return Response.json({ error: 'Invalide' }, { status: 400 });
```

## 6. BODY SIZE LIMITS — DoS

### Limite par défaut dans Next.js

```typescript
// next.config.js
module.exports = {
  experimental: {
    serverActions: {
      bodySizeLimit: '1mb', // default 1MB, ajuster
    },
  },
};

// Pour routes API custom — vérifier Content-Length
export async function POST(request: Request) {
  const contentLength = parseInt(request.headers.get('content-length') ?? '0');
  if (contentLength > 5 * 1024 * 1024) { // 5 Mo
    return Response.json({ error: 'Payload trop volumineux' }, { status: 413 });
  }
  // ...
}
```

### Pagination DoS

```typescript
// ❌ VULNÉRABLE — ?limit=1000000
const limit = parseInt(request.nextUrl.searchParams.get('limit') ?? '20');

// ✅ Limiter côté serveur
const MAX_LIMIT = 100;
const limit = Math.min(parseInt(searchParams.get('limit') ?? '20'), MAX_LIMIT);
```

## 7. ORDER INJECTION — Sort param

Le paramètre `sort` passé directement dans une requête SQL leak les colonnes BDD et permet des ORDER BY arbitraires.

```typescript
// ❌ VULNÉRABLE — order injection
const sort = request.nextUrl.searchParams.get('sort') ?? 'createdAt';
const order = request.nextUrl.searchParams.get('order') ?? 'desc';
const users = await db.$queryRawUnsafe(
  `SELECT * FROM users ORDER BY ${sort} ${order}`
);

// ✅ Whitelist des colonnes autorisées
const ALLOWED_SORT = ['createdAt', 'name', 'email'] as const;
type SortField = typeof ALLOWED_SORT[number];

const sortParam = request.nextUrl.searchParams.get('sort');
const sort: SortField = ALLOWED_SORT.includes(sortParam as SortField) 
  ? sortParam as SortField 
  : 'createdAt';
const order = searchParams.get('order') === 'asc' ? 'asc' : 'desc';

const users = await db.user.findMany({
  orderBy: { [sort]: order },
  take: 20,
});
```

## 8. MASS ASSIGNMENT — Prisma

Prisma ne fait pas de mass assignment par défaut SI tu utilises `select` explicitement. Mais `...req.body` est dangereux.

```typescript
// ❌ VULNÉRABLE — l'utilisateur peut écraser `role`, `isAdmin`, `deletedAt`
const body = await request.json();
await db.user.update({
  where: { id: session.userId },
  data: body, // ⚠️ si body = { name: 'X', role: 'admin' }
});

// ✅ Whitelist explicite
const UpdateSchema = z.object({
  name: z.string().min(2).max(50).optional(),
  email: z.string().email().optional(),
});
const parsed = UpdateSchema.parse(body);
await db.user.update({
  where: { id: session.userId },
  data: parsed.data, // seulement name et email
});
```

## 9. PROTOTYPE POLLUTION

Les fonctions de deep merge (lodash `_.merge`, `_.set`, `_.setWith`) peuvent polluer `Object.prototype` via `__proto__`.

```typescript
// ❌ VULNÉRABLE — lodash.merge
import _ from 'lodash';
const config = _..merge({}, userInput);
// Si userInput = { __proto__: { isAdmin: true } }
// → Object.prototype.isAdmin === true pour TOUS les objets

// ✅ Utiliser _.merge avec garde, ou Object.assign
const config = { ...defaults, ...sanitizedUserInput };

// ✅ Préfixe Object.create(null) pour les objets sensibles
const config = Object.assign(Object.create(null), defaults, sanitizedUserInput);

// ✅ Ou sanitize l'input
function sanitize(obj: any): any {
  if (typeof obj !== 'object' || obj === null) return obj;
  const clean: Record<string, any> = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    clean[k] = sanitize(v);
  }
  return clean;
}
```

## 10. WEBSOCKET SECURITY

### Origin check

```typescript
// server.ts (Socket.IO)
import { Server } from 'socket.io';

const io = new Server(httpServer, {
  cors: {
    origin: process.env.NEXT_PUBLIC_SITE_URL, // ⚠️ jamais '*'
    credentials: true,
  },
});

io.use((socket, next) => {
  const origin = socket.handshake.headers.origin;
  if (origin !== process.env.NEXT_PUBLIC_SITE_URL) {
    return next(new Error('Origin non autorisée'));
  }
  
  // Auth sur handshake — cookie ou token
  const session = parseSessionCookie(socket.handshake.headers.cookie);
  if (!session) {
    return next(new Error('Non authentifié'));
  }
  socket.data.userId = session.userId;
  next();
});

// Rate limit par socket
io.use((socket, next) => {
  socket.use((_, next) => {
    if (rateLimitMemory(`ws:${socket.data.userId}`, 30, '1s')) {
      next();
    } else {
      next(new Error('Rate limit'));
    }
  });
  next();
});

// Taille max des messages
io.use((socket, next) => {
  socket.use((event, next) => {
    const message = event[1];
    if (typeof message === 'string' && message.length > 10_000) {
      return next(new Error('Message trop volumineux'));
    }
    next();
  });
  next();
});
```

## 11. POSTMESSAGE — Validation d'origine

```typescript
// ❌ VULNÉRABLE — n'importe quelle fenêtre peut envoyer des messages
window.addEventListener('message', (event) => {
  if (event.data.type === 'setConfig') {
    localStorage.setItem('config', JSON.stringify(event.data.config));
  }
});

// ✅ OBLIGATOIRE — valider origin ET structure
const ALLOWED_ORIGINS = ['https://embed.example.com'];

window.addEventListener('message', (event) => {
  // 1. Valider l'origine
  if (!ALLOWED_ORIGINS.includes(event.origin)) return;
  
  // 2. Valider la structure
  if (typeof event.data !== 'object' || event.data === null) return;
  if (event.data.type !== 'setConfig') return;
  
  const parsed = ConfigSchema.safeParse(event.data.config);
  if (!parsed.success) return;
  
  // 3. Action
  setConfig(parsed.data);
});

// Coté envoi : toujours préciser targetOrigin
iframe.contentWindow?.postMessage(
  { type: 'config', payload },
  'https://embed.example.com' // ⚠️ jamais '*'
);
```

## 12. EMAIL INFRASTRUCTURE — SPF / DKIM / DMARC

Si l'application envoie des emails (transactionnels ou marketing), ces 3 enregistrements DNS sont obligatoires pour éviter que tes emails ne finissent en spam et pour prévenir l'usurpation de ton domaine (phishing).

### SPF (Sender Policy Framework)

Déclare quels serveurs sont autorisés à envoyer des emails pour ton domaine.

```
# DNS — enregistrement TXT sur ton-domaine.fr
v=spf1 include:_spf.google.com include:sendgrid.net ~all
```

- `~all` = soft fail (marque comme spam mais ne rejette pas)
- `-all` = hard fail (rejette) — recommandé une fois SPF stabilisé

### DKIM (DomainKeys Identified Mail)

Signature cryptographique des emails. Configuration dépend du fournisseur (SendGrid, Postmark, SES, etc.). Ajoute l'enregistrement DNS fourni.

```
# DNS — enregistrement TXT sur selector._domainkey.ton-domaine.fr
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...
```

### DMARC

Politique de traitement des emails qui échouent SPF/DKIM.

```
# DNS — enregistrement TXT sur _dmarc.ton-domaine.fr
v=DMARC1; p=quarantine; rua=mailto:dmarc@ton-domaine.fr; pct=100; adkim=s; aspf=s
```

- `p=none` : monitoring seulement
- `p=quarantine` : spam
- `p=reject` : rejet (recommandé une fois DMARC stabilisé)
- `rua=mailto:...` : rapports agrégés envoyés à cette adresse

**Ordre de déploiement :**
1. SPF `~all` → monitorer 2 semaines
2. DKIM → monitorer 2 semaines
3. DMARC `p=none` → analyser les rapports `rua`
4. DMARC `p=quarantine` → 2 semaines
5. SPF `-all` + DMARC `p=reject` → policy finale

## 13. SUBDOMAIN TAKEOVER

Si tu as un CNAME pointant vers un service supprimé (Heroku app, GitHub Pages, S3 bucket), un attaquant peut réclamer ce nom et servir du contenu sur ton sous-domaine.

### Détection

```bash
# Lister tous les CNAMEs du domaine
dig +short CNAME blog.ton-domaine.fr
# blog-ton-domaine-fr.herokuapp.com

# Tester si la cible existe encore
curl https://blog-ton-domaine-fr.herokuapp.com
# Si "No such app" → VULNÉRABLE
```

### Patterns à surveiller

- `*.herokuapp.com` → "No such app"
- `*.github.io` → 404 "There isn't a GitHub Pages site here"
- `*.s3.amazonaws.com` → "NoSuchBucket"
- `*.elasticbeanstalk.com` → "NXDOMAIN"
- `*.azurewebsites.net` → "404 Web Site not found"

### Mitigation

- **Supprimer** les CNAMEs vers services supprimés (DNS)
- **Monitoring DNS** régulier (outils : Subjack, SubOver, bug bounty)
- **DNSSEC** pour prévenir le cache poisoning

## 14. SUBRESOURCE INTEGRITY (SRI)

Pour tout script/style tiers chargé via CDN, ajouter l'attribut `integrity` pour prévenir la modification du fichier par le CDN compromis.

```html
<!-- ❌ VULNÉRABLE — si cdnjs est compromis, le script s'exécute -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.0.0/react.production.min.js"></script>

<!-- ✅ AVEC SRI -->
<script
  src="https://cdnjs.cloudflare.com/ajax/libs/react/18.0.0/react.production.min.js"
  integrity="sha384-ABC123..."
  crossorigin="anonymous"
></script>
```

Calculer le hash :

```bash
curl -s https://cdnjs.cloudflare.com/ajax/libs/react/18.0.0/react.production.min.js | \
  openssl dgst -sha384 -binary | openssl base64 -A
# → abc...= (préfixer avec "sha384-")
```

Avec Next.js :

```tsx
import Script from 'next/script';

<Script
  src="https://cdnjs.cloudflare.com/..."
  integrity="sha384-..."
  crossOrigin="anonymous"
/>
```

## 15. INFORMATION DISCLOSURE — Patterns à bloquer

### 15.1 User enumeration via registration

```typescript
// ❌ VULNÉRABLE — révèle si l'email existe
if (existingUser) {
  return Response.json({ error: 'Email déjà utilisé' }, { status: 409 });
}

// ✅ Message neutre
return Response.json({ 
  success: true,
  message: 'Si cet email n\'est pas déjà enregistré, un lien de confirmation a été envoyé.'
});
// Envoyer un email different selon que l'email existe ou non :
// - S'il existe : "Vous êtes déjà inscrit, connectez-vous"
// - S'il n'existe pas : "Cliquez pour confirmer"
```

### 15.2 User enumeration via password reset

```typescript
// ✅ Message identique dans tous les cas
return Response.json({
  message: 'Si un compte existe pour cet email, un lien de réinitialisation a été envoyé.'
});
```

### 15.3 `X-Powered-By` header

```typescript
// next.config.js
module.exports = {
  poweredByHeader: false, // supprime "X-Powered-By: Next.js"
};
```

### 15.4 Source maps en production

```typescript
// next.config.js
module.exports = {
  productionBrowserSourceMaps: false, // ✅ DÉFAUT — ne pas activer en prod
  serverSourceMaps: false,
};
```

Si tu veux garder les source maps pour Sentry, configure Sentry pour les servir **à part** (pas depuis `/static/`).

### 15.5 `.git/` exposé

Si un serveur statique sert le dossier du projet (anti-pattern), `.git/` peut être accessible et leak tout l'historique.

```bash
# Vérifier
curl https://ton-site.fr/.git/HEAD
# Si "ref: refs/heads/main" → VULNÉRABLE — toute la base de code leak
```

**Mitigation :**
- Ne jamais déployer `.git/` (Dockerfile multi-stage)
- Vérifier la config nginx/Apache : `location ~ /\.git { deny all; }`
- Pour Next.js/Vercel, le build ne sert jamais `.git/`

### 15.6 Stack traces dans les réponses

```typescript
// ❌ INTERDIT
return Response.json({ error: err.message, stack: err.stack }, { status: 500 });

// ✅ Logger en interne, message générique au client
logger.error('unhandled', { error: err.message, stack: err.stack });
return Response.json({ error: 'internal_error' }, { status: 500 });
```

## 16. CACHE SECURITY

### Pages authentifiées — jamais de cache

```typescript
// app/dashboard/page.tsx
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const response = Response.json(data);
  // Pour tout contenu authentifié
  response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  response.headers.set('Pragma', 'no-cache');
  response.headers.set('Expires', '0');
  return response;
}
```

### CDN — `Vary: Cookie`

Si tu fais du cache-edge (Cloudflare, Vercel Edge) avec contenu personnalisé :

```typescript
response.headers.set('Vary', 'Cookie');
// Sinon, le CDN peut servir la page de l'utilisateur A à l'utilisateur B
```

### Logout — invalider le cache

```typescript
export async function POST(request: Request) {
  // Invalider session serveur
  await invalidateSession(session.id);
  
  // Effacer cookies
  const response = Response.json({ success: true });
  response.cookies.delete('__Host-session');
  
  // Cache-Control sur la réponse de logout
  response.headers.set('Cache-Control', 'no-store');
  
  return response;
}
```

## 17. OAUTH / OIDC — Connexion tierce (Google, GitHub, etc.)

### State parameter (CSRF)

```typescript
// ❌ VULNÉRABLE — pas de state = CSRF
const authUrl = `https://accounts.google.com/oauth/authorize?client_id=...&redirect_uri=...`;

// ✅ State aléatoire stocké en cookie court
import { randomBytes } from 'crypto';

const state = randomBytes(32).toString('hex');
cookies().set('oauth_state', state, {
  httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600, path: '/',
});

const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID!);
authUrl.searchParams.set('redirect_uri', redirectUri);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('scope', 'openid email profile');

return Response.redirect(authUrl);
```

```typescript
// Callback — vérifier state
const { code, state } = request.nextUrl.searchParams;
const savedState = cookies().get('oauth_state')?.value;

if (!state || state !== savedState) {
  return Response.json({ error: 'State mismatch' }, { status: 400 });
}
cookies().delete('oauth_state');
```

### PKCE pour SPA / mobile

```typescript
import { randomBytes, createHash } from 'crypto';

const codeVerifier = randomBytes(32).toString('base64url');
const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

// Stocker codeVerifier en cookie court
cookies().set('pkce_verifier', codeVerifier, { /* ... */ maxAge: 600 });

// Envoyer codeChallenge dans l'URL d'auth
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// Au callback, envoyer codeVerifier lors du token exchange
const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
  method: 'POST',
  body: new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID!,
    client_secret: process.env.GOOGLE_CLIENT_SECRET!,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier, // ← PKCE
  }),
});
```

### Redirect URI strict matching

```typescript
const ALLOWED_REDIRECT_URIS = [
  'https://ton-domaine.fr/api/auth/callback/google',
];

const redirectUri = request.nextUrl.searchParams.get('redirect_uri');
if (!ALLOWED_REDIRECT_URIS.includes(redirectUri!)) {
  return Response.json({ error: 'Redirect URI non autorisé' }, { status: 400 });
}
// ⚠️ Jamais de matching par prefixe ou regex lâche
```

### Validation de l'ID token

```typescript
import { jwtVerify } from 'jose';

const jwks = await getGoogleJWKS(); // cache des clés publiques
const { payload } = await jwtVerify(idToken, jwks, {
  issuer: 'https://accounts.google.com',
  audience: process.env.GOOGLE_CLIENT_ID,
});

// Vérifier que l'email est vérifié par Google
if (!payload.email_verified) {
  return Response.json({ error: 'Email non vérifié' }, { status: 400 });
}
```

## 18. SUPPLY CHAIN SECURITY

### Lockfile commité

```bash
# package-lock.json OU yarn.lock OU pnpm-lock.yaml DOIT être commité
git add package-lock.json
```

### Audit régulier

```bash
npm audit --audit-level=high
# En CI :
npm audit --audit-level=high --omit=dev || exit 1
```

### Branch protection (GitHub)

- Branche `main` : pas de push direct, PR obligatoire
- Reviews obligatoires (min 1, idéalement 2 pour code critique)
- Status checks obligatoires (CI, audit, typecheck)
- Pas de force-push sur `main`
- Pas de suppression de `main`

### SBOM (Software Bill of Materials)

Générer un SBOM CycloneDX ou SPDX à chaque release :

```bash
npm install -g @cyclonedx/cyclonedx-cli
cyclonedx-npm --output-file sbom.json --output-format json
```

### Docker — ne pas tourner en root

```dockerfile
FROM node:20-alpine AS base
WORKDIR /app

# Build stage
FROM base AS builder
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM base AS runner
# ✅ Créer user non-root
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001 -G nodejs
USER nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
```

### Pre/post install scripts

```bash
# Désactiver les scripts d'install par défaut (sécurité)
npm config set ignore-scripts true
# Puis les activer explicitement pour les packages de confiance
npm config set ignore-scripts false --location=package
```

## 19. BUILD & CI SECURITY

### Secrets en CI

- **Jamais** de secret en clair dans `.github/workflows/*.yml`
- Utiliser GitHub Actions secrets (Settings → Secrets)
- Masker les sorties qui pourraient contenir des secrets

```yaml
- name: Deploy
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
  run: npm run deploy
```

### Signed commits

```bash
# Configurer GPG ou SSH signing
git config --global commit.gpgsign true
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519
```

### Dependabot / Renovate

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
```

## 20. NEXT_PUBLIC_ LEAK — Variables d'env exposées au client

Toute variable préfixée `NEXT_PUBLIC_` est inline dans le bundle JavaScript client. **Ne jamais y mettre un secret.**

```bash
# ❌ DANGEREUX — leaked dans le bundle client
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_123
NEXT_PUBLIC_DATABASE_URL=postgres://...
NEXT_PUBLIC_JWT_SECRET=...

# ✅ OK — clés PUBLIQUES (pas de secret)
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_123
NEXT_PUBLIC_GA_ID=G-XXXXXX
NEXT_PUBLIC_SITE_URL=https://example.com
```

### Vérification

```bash
# Chercher les NEXT_PUBLIC_ dans le code
rg "NEXT_PUBLIC_" --type ts

# Vérifier le bundle généré
grep -r "sk_live\|sk_test\|password\|secret" .next/static/chunks/
# Si tu trouves un secret → LEAK critique
```
