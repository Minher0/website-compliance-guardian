# FRONTEND — Forms, appels client, UX sécurité

Ce fichier définit les règles obligatoires pour tout code frontend : composants React, formulaires, appels API client, gestion d'état, rendu HTML.

## 1. FORMULAIRES — Règles de sécurité et UX

### Validation côté client ET côté serveur

**Règle absolue :** La validation côté serveur est obligatoire. La validation côté client est une amélioration UX mais ne remplace jamais la validation serveur (le client est hostile).

### Schéma Zod partagé client/serveur

```typescript
// schemas/auth.ts — importé côté client ET serveur
import { z } from 'zod';

export const RegisterSchema = z.object({
  email: z.string().email('Email invalide'),
  password: z.string()
    .min(12, '12 caractères minimum')
    .regex(/[A-Z]/, 'Une majuscule requise')
    .regex(/[a-z]/, 'Une minuscule requise')
    .regex(/[0-9]/, 'Un chiffre requis')
    .regex(/[^A-Za-z0-9]/, 'Un caractère spécial requis'),
  confirmPassword: z.string(),
  acceptTerms: z.literal(true, {
    errorMap: () => ({ message: 'Vous devez accepter les CGU et la politique de confidentialité' }),
  }),
}).refine(data => data.password === data.confirmPassword, {
  message: 'Les mots de passe ne correspondent pas',
  path: ['confirmPassword'],
});

export type RegisterInput = z.infer<typeof RegisterSchema>;
```

### Formulaire React avec react-hook-form

```tsx
// components/auth/register-form.tsx
'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { RegisterSchema } from '@/schemas/auth';
import { apiFetch } from '@/lib/api';

export function RegisterForm() {
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(RegisterSchema),
    defaultValues: { acceptTerms: false as unknown as true },
  });

  const onSubmit = async (data: RegisterInput) => {
    try {
      await apiFetch('POST /api/auth/register', {
        body: data,
        csrf: true,
      });
      // Rediriger vers login
    } catch (error) {
      if (error.code === 'email_taken') {
        setError('email', { message: 'Cet email est déjà utilisé' });
      } else {
        setError('root', { message: 'Une erreur est survenue' });
      }
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      {/* Champ email */}
      <label htmlFor="email">Email</label>
      <input
        id="email"
        type="email"
        autoComplete="email"
        {...register('email')}
        aria-invalid={!!errors.email}
        aria-describedby={errors.email ? 'email-error' : undefined}
      />
      {errors.email && <p id="email-error" role="alert">{errors.email.message}</p>}

      {/* Champ password */}
      <label htmlFor="password">Mot de passe</label>
      <input
        id="password"
        type="password"
        autoComplete="new-password"
        {...register('password')}
        aria-describedby="password-hint"
      />
      <p id="password-hint">12 caractères min, 1 majuscule, 1 chiffre, 1 spécial</p>
      {errors.password && <p role="alert">{errors.password.message}</p>}

      {/* Case CGU */}
      <label>
        <input type="checkbox" {...register('acceptTerms')} />
        J'accepte les <a href="/cgu">CGU</a> et la <a href="/privacy">politique de confidentialité</a>
      </label>
      {errors.acceptTerms && <p role="alert">{errors.acceptTerms.message}</p>}

      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Création...' : 'Créer mon compte'}
      </button>
    </form>
  );
}
```

### Règles d'accessibilité des formulaires (RGAA 4.1)

- **`<label>`** associé via `htmlFor`/`id` pour tout champ
- **`aria-invalid`** et **`aria-describedby`** pour les erreurs
- **`role="alert"`** sur les messages d'erreur
- **`autoComplete`** correct pour remplissage password manager (`new-password`, `current-password`, `email`, `tel`, `street-address`)
- **Ordre tabulation** logique (tabindex naturel via ordre DOM)
- **Contraste** AA (4.5:1 texte normal, 3:1 gros texte)
- **Taille cible tactile** : 44x44 CSS px minimum

### Anti-soumission multiple

```tsx
<button type="submit" disabled={isSubmitting}>
  {isSubmitting ? 'Envoi...' : 'Envoyer'}
</button>
```

**Règle :** Tout formulaire de mutation doit désactiver le bouton pendant la soumission.

## 2. APPELS API CLIENT — Règles

### Client type-safe centralisé

```typescript
// lib/api.ts
import { API_ROUTES, RouteKey } from '@/lib/route-map';

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export async function apiFetch<K extends RouteKey>(
  route: K,
  options: { params?: Record<string, string>; body?: unknown; csrf?: boolean } = {}
) {
  const [method, pathTemplate] = route.split(' ') as [string, string];
  let path = pathTemplate;
  if (options.params) {
    for (const [k, v] of Object.entries(options.params)) {
      path = path.replace(`:${k}`, encodeURIComponent(v));
    }
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (options.csrf) {
    const csrfToken = document.cookie
      .split('; ')
      .find(c => c.startsWith('csrf_token='))
      ?.split('=')[1];
    if (!csrfToken) throw new Error('CSRF token missing');
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ code: 'network', message: 'Network error' }));
    throw new ApiError(response.status, error.code, error.message);
  }

  return response.json();
}
```

### Règles obligatoires

- **Toujours `credentials: 'same-origin'`** pour les cookies de session
- **Toujours valider la réponse** (Zod) si elle vient d'une source externe
- **Toujours catcher** les erreurs et afficher un message utilisateur
- **Jamais construire une URL** avec `fetch(\`/api/users/${id}\`)` — passer par `apiFetch` pour valider la route existe
- **Jamais appeler une URL absolue** `https://api.example.com/...` sans validation — préférer un proxy via `/api/external/[...]`

### SWR / TanStack Query — patterns

```tsx
// ✅ BON — SWR avec typage et gestion d'erreur
import useSWR from 'swr';

function useUser(id: string) {
  return useSWR(
    id ? `/api/users/${id}` : null,
    (url) => apiFetch('GET /api/users/:id', { params: { id } }),
    {
      onErrorRetry: (error, key, config, revalidate, { retryCount }) => {
        if (error.status === 404) return; // pas de retry sur 404
        if (retryCount >= 3) return;
        setTimeout(() => revalidate({ retryCount }), 2000);
      },
    }
  );
}

// ❌ MAUVAIS — fetch direct, pas de typage, pas de gestion d'erreur
const response = await fetch(`/api/users/${id}`);
const user = await response.json();
```

## 3. XSS — Échappement du rendu

### React échappe par défaut

```tsx
const userName = '<script>alert(1)</script>';
return <div>{userName}</div>; // ✅ SÉCURISÉ — React échappe
```

### `dangerouslySetInnerHTML` — Interdit sans sanitization

```tsx
// ❌ INTERDIT — XSS stored
return <div dangerouslySetInnerHTML={{ __html: userBio }} />;

// ✅ OBLIGATOIRE — sanitize d'abord
import DOMPurify from 'isomorphic-dompurify';
return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />;
```

### URLs dynamiques — Validation de schéma

```tsx
// ❌ INTERDIT — open redirect / javascript: XSS
return <a href={userUrl}>Click</a>; // si userUrl = "javascript:alert(1)"

// ✅ OBLIGATOIRE — valider le schéma
function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    return ['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

return <a href={isSafeUrl(userUrl) ? userUrl : '#'}>Click</a>;
```

### `target="_blank"` — Toujours `rel="noopener noreferrer"`

```tsx
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Lien externe</a>
```

## 4. STORAGE CLIENT — Règles strictes

### localStorage / sessionStorage

**Jamais** y stocker :
- Tokens d'auth (JWT, session) → utiliser des cookies HttpOnly
- Données personnelles (email, nom, téléphone)
- Données sensibles (carte, santé)
- Secrets API

**Autorisé :**
- Préférences UI (thème, langue)
- État UI éphémère (panier avant auth, formulaires en brouillon NON sensibles)
- Consentement cookies (la preuve de consentement, pas le consentement lui-même)

### Tokens en mémoire uniquement (si JWT dans header)

Si tu dois utiliser Bearer token (pas de cookie HttpOnly possible), stocke-le en mémoire (variable JS) et utilise un refresh token en cookie HttpOnly pour le régénérer à chaque rechargement.

```tsx
// ❌ INTERDIT
localStorage.setItem('token', jwt);
sessionStorage.setItem('token', jwt);

// ✅ Acceptable (avec refresh en cookie HttpOnly)
let accessToken: string | null = null;
export function setToken(token: string) { accessToken = token; }
export function getToken() { return accessToken; }
```

## 5. CSP — Adaptation côté client

### Nonces pour scripts inline

Si tu dois inline du script en Next.js, utiliser les nonces CSP :

```tsx
// app/layout.tsx
import { headers } from 'next/headers';

export default async function RootLayout({ children }) {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <html>
      <body>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: '...' }} />
        {children}
      </body>
    </html>
  );
}
```

### Next.js Script component

```tsx
// ✅ BON
import Script from 'next/script';
<Script src="https://analytics.example.com/tracker.js" strategy="afterInteractive" />

// ❌ À ÉVITER si pas consentement
<script src="https://analytics.example.com/tracker.js" />
```

## 6. UX SÉCURITÉ — Patterns recommandés

### Indicateur de force du mot de passe

```tsx
function PasswordStrength({ password }: { password: string }) {
  const score = computeScore(password); // 0-4
  const labels = ['Très faible', 'Faible', 'Moyen', 'Bon', 'Excellent'];
  const colors = ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#15803d'];
  return (
    <div>
      <div className="h-2 w-full bg-gray-200 rounded">
        <div 
          className="h-2 rounded transition-all" 
          style={{ width: `${(score + 1) * 20}%`, backgroundColor: colors[score] }}
          role="progressbar"
          aria-valuenow={score + 1}
          aria-valuemin={1}
          aria-valuemax={5}
        />
      </div>
      <p style={{ color: colors[score] }}>{labels[score]}</p>
    </div>
  );
}
```

### Bouton "Afficher le mot de passe"

Toujours proposer un toggle `type="password" ↔ type="text"` pour le mot de passe, avec `aria-label` clair.

### Confirmation avant action destructrice

```tsx
function DeleteAccountButton() {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return <button onClick={() => setConfirming(true)}>Supprimer mon compte</button>;
  }
  return (
    <div role="alertdialog" aria-labelledby="confirm-title">
      <h2 id="confirm-title">Confirmer la suppression</h2>
      <p>Cette action est irréversible. Toutes vos données seront supprimées.</p>
      <button onClick={handleDelete}>Confirmer</button>
      <button onClick={() => setConfirming(false)}>Annuler</button>
    </div>
  );
}
```

### Messages d'erreur — Ne pas fuite d'information

```tsx
// ❌ INTERDIT — révèle si l'email existe
{error.code === 'user_not_found' && <p>Email non enregistré</p>}
{error.code === 'wrong_password' && <p>Mot de passe incorrect</p>}

// ✅ OBLIGATOIRE — message générique
{error.code === 'invalid_credentials' && <p>Email ou mot de passe incorrect</p>}
```

## 7. AUTH FRONTEND — Patterns

### Vérification d'auth au chargement

```tsx
// app/(protected)/layout.tsx
import { redirect } from 'next/navigation';
import { getSession } from '@/lib/auth-server';

export default async function ProtectedLayout({ children }) {
  const session = await getSession();
  if (!session) redirect('/login?from=' + encodeURIComponent(currentPath));
  return <>{children}</>;
}
```

### Redirection après login

```tsx
const from = searchParams.get('from');
router.push(from || '/dashboard');
// ✅ Valider que `from` est une URL relative
if (from && !from.startsWith('/')) throw new Error('Invalid redirect');
```

### Logout

```tsx
async function handleLogout() {
  await apiFetch('POST /api/auth/logout', { csrf: true });
  // Le serveur doit invalider la session ET effacer les cookies
  router.push('/');
  router.refresh();
}
```

## 8. RENDU — Anti-fuite d'informations

### Ne jamais exposer dans le HTML rendu

- Tokens, secrets, mots de passe
- ID internes sensibles (UUID OK, ID séquentiels DB — éviter)
- Données d'autres utilisateurs
- Stack traces
- Configuration serveur

### Server Components vs Client Components

```tsx
// ✅ BON — Server Component par défaut, données serveur invisibles au client
// app/users/page.tsx
export default async function UsersPage() {
  const users = await db.user.findMany({ select: { id: true, name: true } });
  return <UserList users={users} />;
}

// ✅ Marquer 'use client' SEULEMENT quand nécessaire (state, events, browser APIs)
'use client';
import { useState } from 'react';
```

**Règle :** Préférer Server Components par défaut. Marquer `'use client'` uniquement pour les composants interactifs. Les données sensibles passées à un Client Component sont visibles dans le bundle.

## 9. IMAGES ET FICHIERS — Sécurité

### Upload côté client

```tsx
const ACCEPTED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024; // 5 MB

function validateFile(file: File): string | null {
  if (!ACCEPTED_TYPES.includes(file.type)) return 'Format non supporté';
  if (file.size > MAX_SIZE) return 'Fichier trop volumineux (max 5 Mo)';
  return null;
}
```

### Affichage d'images utilisateur

Toujours utiliser `next/image` avec `unoptimized` uniquement si l'origine est non fiable, sinon configurer les domaines :

```js
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'cdn.example.com' },
    ],
  },
};
```

## 10. HYDRATATION — Éviter les erreurs

Pour éviter les mismatches SSR/CSR qui causent des failles (ex: token qui apparaît puis disparaît) :

```tsx
// ✅ BON —Mounted pattern pour valeurs spécifiques au client
'use client';
import { useEffect, useState } from 'react';

export function ClientOnly({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;
  return <>{children}</>;
}
```

## 11. POSTMESSAGE — Validation d'origine obligatoire

```typescript
// ❌ INTERDIT — n'importe quelle fenêtre peut envoyer des messages
window.addEventListener('message', (event) => {
  if (event.data.type === 'setConfig') {
    localStorage.setItem('config', JSON.stringify(event.data.config));
  }
});

// ✅ TOUJOURS valider origin + structure
const ALLOWED_ORIGINS = ['https://embed.example.com'];

window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.includes(event.origin)) return; // 1. Origin
  if (typeof event.data !== 'object' || event.data === null) return; // 2. Type
  if (event.data.type !== 'setConfig') return;
  
  const parsed = ConfigSchema.safeParse(event.data.config); // 3. Zod
  if (!parsed.success) return;
  
  setConfig(parsed.data);
});

// À l'envoi : toujours préciser targetOrigin (jamais '*')
iframe.contentWindow?.postMessage(
  { type: 'config', payload },
  'https://embed.example.com'
);
```

## 12. SERVICE WORKER — Sécurité & cache

### HTTPS obligatoire

Les service workers ne fonctionnent qu'en HTTPS (ou `localhost` en dev). Si tu déploies en HTTP, ça casse silencieusement.

### Consentement pour le cache personnalisé

Un service worker peut cacher des données personnelles (panier, préférences). Si l'utilisateur retire son consentement, **vider le cache** :

```typescript
// public/sw.js
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('v1').then((cache) => cache.addAll([
      '/',
      '/static/css/main.css',
      // ⚠️ Ne JAMAIS cacher des pages authentifiées ici
    ]))
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Pas de cache pour les routes API authentifiées
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/dashboard')) {
    return; // laisse passer la requête normalement
  }
  
  // Cache-first pour les assets statiques
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(caches.match(event.request));
    return;
  }
  
  // Network-first pour le reste
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

// Écouter les messages de consentement
self.addEventListener('message', (event) => {
  if (event.data?.type === 'CLEAR_CACHE') {
    caches.keys().then((keys) => 
      Promise.all(keys.map((k) => caches.delete(k)))
    );
  }
});
```

### Enregistrement conditionnel

```typescript
// Enregistrer le SW UNIQUEMENT après consentement
if (consent?.functional) {
  navigator.serviceWorker.register('/sw.js');
}
```

## 13. NEXT_PUBLIC_ LEAK — Vérification du bundle

Toute variable `NEXT_PUBLIC_*` est inline dans le bundle client. **Aucun secret ne doit l'être.**

```typescript
// ❌ FUITE CRITIQUE — ce secret est dans le JS téléchargé par tous les visiteurs
process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY
process.env.NEXT_PUBLIC_JWT_SECRET
process.env.NEXT_PUBLIC_DATABASE_URL

// ✅ OK — clés publiques uniquement
process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY  // pk_live_*
process.env.NEXT_PUBLIC_GA_ID                    // G-XXXXXX
process.env.NEXT_PUBLIC_SITE_URL                // https://...
```

### Vérifier après build

```bash
# Build de production
npm run build

# Chercher les secrets dans le bundle
grep -rE "(sk_live_|sk_test_|password|secret|token|api_key)" .next/static/chunks/
# Si retour non vide → FUITE CRITIQUE

# Lister toutes les NEXT_PUBLIC_ exposées
grep -roE "NEXT_PUBLIC_[A-Z_]+" .next/static/chunks/ | sort -u
```
