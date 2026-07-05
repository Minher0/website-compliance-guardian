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
