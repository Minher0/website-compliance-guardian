# BACKEND — Routes API, validation, logique serveur

Ce fichier définit les règles obligatoires pour tout code backend : routes API, middleware, services, accès BDD, jobs asynchrones.

## 1. STRUCTURE OBLIGATOIRE D'UNE ROUTE API

Toute route API doit respecter cet ordre :

1. **Rate limiting** (si endpoint public sensible)
2. **Authentification** (si endpoint non public)
3. **Autorisation** (rôle / propriété ressource)
4. **CSRF check** (si mutation depuis navigateur)
5. **Validation des entrées** (Zod)
6. **Logique métier**
7. **Audit log** (pour actions sensibles)
8. **Réponse** (sans fuite de donnée)

```typescript
// app/api/users/[id]/route.ts
import { z } from 'zod';
import { auth } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';
import { verifyCsrf } from '@/lib/csrf';
import { logger } from '@/lib/logger';
import { db } from '@/lib/db';

const UpdateUserSchema = z.object({
  name: z.string().min(2).max(50).optional(),
  email: z.string().email().optional(),
});

export async function PATCH(
  request: Request,
  { params }: { params: { id: string } }
) {
  // 1. Rate limit
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ?? 'unknown';
  const { success: rlOk } = await rateLimit(`user-update:${ip}`, 20, '1m');
  if (!rlOk) return Response.json({ error: 'Too many requests' }, { status: 429 });

  // 2. Auth
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  // 3. Autorisation — l'utilisateur ne peut modifier QUE son propre profil (sauf admin)
  if (session.userId !== params.id && !session.roles.includes('admin')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // 4. CSRF
  if (!verifyCsrf(request)) {
    return Response.json({ error: 'CSRF invalid' }, { status: 403 });
  }

  // 5. Validation
  const body = await request.json();
  const parsed = UpdateUserSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json({ error: 'Validation failed', issues: parsed.error.issues }, { status: 400 });
  }

  // 6. Logique métier
  const updated = await db.user.update({
    where: { id: params.id },
    data: parsed.data,
    select: { id: true, name: true, email: true }, // ne jamais retourner passwordHash
  });

  // 7. Audit log
  await logger.audit('user.updated', {
    actorId: session.userId,
    targetId: params.id,
    changes: Object.keys(parsed.data),
  });

  // 8. Réponse
  return Response.json(updated);
}
```

## 2. VALIDATION DES ENTRÉES — Obligatoire

**Règle absolue :** Toute entrée HTTP (body, query, params, headers) doit être validée par un schéma avant utilisation. Jamais de `req.body.champ` direct.

### Schémas Zod

```typescript
// schemas/user.ts
import { z } from 'zod';

export const CreateUserSchema = z.object({
  email: z.string().email('Email invalide').max(254),
  password: z.string()
    .min(12, 'Mot de passe trop court (min 12)')
    .max(128)
    .regex(/[A-Z]/, 'Au moins une majuscule')
    .regex(/[a-z]/, 'Au moins une minuscule')
    .regex(/[0-9]/, 'Au moins un chiffre')
    .regex(/[^A-Za-z0-9]/, 'Au moins un caractère spécial'),
  name: z.string().min(2).max(50),
  acceptTerms: z.literal(true, {
    errorMap: () => ({ message: 'Vous devez accepter les conditions' }),
  }),
});

export type CreateUserInput = z.infer<typeof CreateUserSchema>;
```

### Validation dans la route

```typescript
const parsed = CreateUserSchema.safeParse(body);
if (!parsed.success) {
  return Response.json(
    { error: 'Données invalides', issues: parsed.error.flatten().fieldErrors },
    { status: 400 }
  );
}
const { email, password, name } = parsed.data;
```

### Validation des query params

```typescript
const ListUsersSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.enum(['createdAt', 'name']).default('createdAt'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

const url = new URL(request.url);
const parsed = ListUsersSchema.safeParse(Object.fromEntries(url.searchParams));
if (!parsed.success) return Response.json({ error: 'Query invalide' }, { status: 400 });
```

## 3. COHÉRENCE DES ROUTES — Vérification d'existence

**Règle absolue :** Avant d'appeler une route côté client, vérifier qu'elle existe côté serveur.

### Checklist de cohérence

Pour chaque `fetch('/api/...')` côté client, vérifier :

1. Le fichier de route existe (`app/api/<path>/route.ts` ou `pages/api/<path>.ts`)
2. La méthode HTTP (GET/POST/PATCH/DELETE) est exportée
3. Le chemin correspond exactement (attention aux `/` et `[param]`)
4. Le schéma de réponse attendu correspond à ce que la route renvoie

### Outil de vérification automatique

Le skill doit générer un fichier `route-map.ts` automatiquement, listant toutes les routes serveur et leurs signatures, pour validation client :

```typescript
// lib/route-map.ts (auto-generated)
export const API_ROUTES = {
  'POST /api/auth/login': { body: LoginInput, response: LoginResponse },
  'POST /api/auth/register': { body: RegisterInput, response: RegisterResponse },
  'GET /api/users/:id': { params: { id: string }, response: UserResponse },
  'PATCH /api/users/:id': { body: UpdateUserInput, response: UserResponse },
  'DELETE /api/account': { body: { password: string }, response: { success: boolean } },
} as const;

// Utilisation côté client
import { apiFetch } from '@/lib/api';
const result = await apiFetch('PATCH /api/users/:id', {
  params: { id: userId },
  body: { name: 'Alice' },
});
```

```typescript
// lib/api.ts — client type-safe
import { API_ROUTES } from '@/lib/route-map';

type RouteKey = keyof typeof API_ROUTES;

export async function apiFetch<K extends RouteKey>(
  route: K,
  options: { params?: Record<string, string>; body?: unknown; csrf?: boolean }
): Promise<...> {
  const [method, pathTemplate] = route.split(' ');
  let path = pathTemplate;
  if (options.params) {
    for (const [k, v] of Object.entries(options.params)) {
      path = path.replace(`:${k}`, encodeURIComponent(v));
    }
  }
  
  const response = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(options.csrf ? { 'X-CSRF-Token': getCsrfToken() } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Network error' }));
    throw new ApiError(response.status, error);
  }
  return response.json();
}
```

## 4. PROTECTION DES RESSOURCES — Vérification d'appartenance

**Règle :** Toujours vérifier que l'utilisateur authentifié a le droit d'accéder à la ressource demandée.

```typescript
// ❌ INTERDIT — IDOR (Insecure Direct Object Reference)
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  const order = await db.order.findUnique({ where: { id: params.id } });
  return Response.json(order); // n'importe quel user peut lire n'importe quelle commande
}

// ✅ OBLIGATOIRE
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  
  const order = await db.order.findUnique({ where: { id: params.id } });
  if (!order) return Response.json({ error: 'Not found' }, { status: 404 });
  
  // Vérification d'appartenance
  if (order.userId !== session.userId && !session.roles.includes('admin')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }
  
  return Response.json(order);
}
```

## 5. ERREURS — Format standardisé

```typescript
// lib/api-error.ts
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
  }
}

// Middleware de gestion d'erreurs
export function withErrorHandler(handler: Function) {
  return async (...args: any[]) => {
    try {
      return await handler(...args);
    } catch (error) {
      if (error instanceof ApiError) {
        return Response.json(
          { error: error.code, message: error.message, details: error.details },
          { status: error.status }
        );
      }
      if (error instanceof z.ZodError) {
        return Response.json(
          { error: 'validation_failed', issues: error.flatten() },
          { status: 400 }
        );
      }
      // Erreur non gérée — loguer en interne, ne pas exposer le détail
      logger.error('unhandled_error', { error: error.message, stack: error.stack });
      return Response.json(
        { error: 'internal_error', message: 'Une erreur est survenue' },
        { status: 500 }
      );
    }
  };
}
```

**Règles :**
- Jamais exposer le stack trace au client en production
- Messages d'erreur génériques pour erreurs 500
- Codes d'erreur explicites pour erreurs 4xx (`'validation_failed'`, `'unauthorized'`, `'forbidden'`, `'not_found'`, `'rate_limited'`, `'conflict'`)

## 6. BASE DE DONNÉES — Règles

### Requêtes paramétrées

```typescript
// ❌ INTERDIT
await db.$queryRaw(`SELECT * FROM users WHERE email = '${email}'`);

// ✅ OBLIGATOIRE — Prisma paramétré
await db.user.findFirst({ where: { email } });

// ✅ Si raw SQL obligatoire
await db.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
```

### Sélection explicite — Jamais de `select: *`

```typescript
// ❌ INTERDIT — renvoie passwordHash
const user = await db.user.findUnique({ where: { id } });

// ✅ OBLIGATOIRE — select explicite
const user = await db.user.findUnique({
  where: { id },
  select: { id: true, email: true, name: true, role: true, createdAt: true },
});
```

### Transactions pour opérations multi-tables

```typescript
await db.$transaction(async (tx) => {
  const order = await tx.order.create({ data: orderData });
  await tx.orderItem.createMany({ data: items.map(i => ({ ...i, orderId: order.id })) });
  await tx.inventory.update({ where: { id }, data: { stock: { decrement: 1 } } });
});
```

### Soft delete vs Hard delete

- **Soft delete** (`deletedAt` non null) : recommandé pour RGPD (preuve d'existence passée, restauration)
- **Hard delete** : pour droit à l'oubli explicite
- **Anonymisation** : compromis — garder l'ID, anonymiser les champs perso

## 7. MIDDLEWARE — Orchestration

```typescript
// lib/middleware-chain.ts
type Middleware = (req: Request, next: () => Promise<Response>) => Promise<Response>;

export function compose(...middlewares: Middleware[]) {
  return async (req: Request): Promise<Response> => {
    let i = 0;
    const next = async () => {
      if (i >= middlewares.length) return new Response(null, { status: 404 });
      const mw = middlewares[i++];
      return mw(req, next);
    };
    return next();
  };
}

// Utilisation
export const GET = compose(
  withRateLimit({ max: 100, window: '1m' }),
  withAuth(),
  withRole(['admin']),
  withCsrf(),
  handler
);
```

## 8. JOBS ASYNCHRONES — Sécurité

### Background jobs (BullMQ, Inngest, Vercel Cron)

- **Authentification** : un job n'est déclenché que par un événement interne ou un webhook signé
- **Idempotence** : un job peut être rejoué sans effet de bord
- **Timeout** : défini et respecté
- **Retry** : limité (3 max), exponential backoff
- **Dead letter queue** : échecs persistants isolés et alertés

### Cron jobs

```typescript
// app/api/cron/purge/sessions/route.ts
export async function GET(request: Request) {
  // Vérifier le secret de cron
  const authHeader = request.headers.get('authorization');
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  // Purge des sessions expirées
  await db.session.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  
  return Response.json({ purged: true });
}
```

```yaml
# vercel.json
{
  "crons": [
    { "path": "/api/cron/purge/sessions", "schedule": "0 3 * * *" }
  ]
}
```

## 9. WEBHOOKS — Vérification des signatures

Tout webhook reçu doit vérifier sa signature avec le secret partagé.

```typescript
// app/api/webhooks/stripe/route.ts
import Stripe from 'stripe';

export async function POST(request: Request) {
  const body = await request.text(); // IMPORTANT: text() pas json()
  const signature = request.headers.get('stripe-signature');
  
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature!,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    logger.security('webhook_signature_failed', { service: 'stripe' });
    return Response.json({ error: 'Invalid signature' }, { status: 400 });
  }
  
  // Traitement idempotent
  await processStripeEvent(event);
  return Response.json({ received: true });
}
```

## 10. ENVIRONNEMENT — Sécurité runtime

```typescript
// lib/env.ts — validation des variables d'environnement
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  ENCRYPTION_KEY: z.string().length(64), // 32 bytes en hex
  NEXTAUTH_URL: z.string().url(),
  // ...
});

export const env = EnvSchema.parse(process.env);
```

**Règle :** L'app doit fail-fast au démarrage si une variable obligatoire manque ou est invalide. Ne jamais attendre un runtime error sur un appel.

## 11. LOGS SERVEUR — Structure

```typescript
// lib/logger.ts
type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'security' | 'audit';

export const logger = {
  info: (message: string, meta?: object) => log('info', message, meta),
  warn: (message: string, meta?: object) => log('warn', message, meta),
  error: (message: string, meta?: object) => log('error', message, meta),
  security: (event: string, meta?: object) => log('security', event, { ...meta, _type: 'security' }),
  audit: (action: string, meta: object) => log('audit', action, { ...meta, _type: 'audit', timestamp: new Date().toISOString() }),
};

function log(level: LogLevel, message: string, meta?: object) {
  const entry = { level, message, timestamp: new Date().toISOString(), ...meta };
  // En prod : vers service externe (Sentry, Datadog, Loki)
  // En dev : console
  if (process.env.NODE_ENV === 'production') {
    console.log(JSON.stringify(entry));
  } else {
    console.log(`[${level}] ${message}`, meta ?? '');
  }
}
```

**À NE JAMAIS logger :**
- Passwords (même hashés)
- Tokens JWT complets
- Numéros de carte (utiliser `<last4>` seulement)
- Données de santé
- Email complet en clair (masquer : `a***@example.com`)
