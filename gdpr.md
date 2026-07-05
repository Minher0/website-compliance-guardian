# RGPD — Conformité légale France & Union Européenne

Ce fichier définit les règles obligatoires de conformité au RGPD (Règlement UE 2016/679), à la Loi Informatique et Libertés (78-17 modifiée), à la directive ePrivacy, et aux recommandations CNIL. Ces règles s'appliquent à tout traitement de données personnelles dans une application web.

## 1. DÉFINITION — Donnée personnelle

Toute information permettant d'identifier directement ou indirectement une personne physique est une donnée personnelle :

- Nom, prénom
- Email
- Numéro de téléphone
- Adresse IP (jurisprudence CJUE — affaire Breyer C-582/14)
- Identifiant cookie
- Identifiant de session
- Géolocalisation
- Données biométriques
- Données de santé
- Données bancaires (hors carte elle-même, gérée par PCI-DSS)

**Règle :** Si tu hésites à savoir si une donnée est personnelle, traite-la comme personnelle.

## 2. PRINCIPES FONDAMENTAUX (Article 5 RGPD)

Pour tout traitement de données, vérifier :

1. **Licéité, loyauté, transparence** — base légale (consentement, contrat, intérêt légitime, obligation légale)
2. **Limitation des finalités** — usage spécifié, explicite, légitime. Pas de réutilisation pour un autre but sans nouveau consentement.
3. **Minimisation** — collecter uniquement ce qui est nécessaire
4. **Exactitude** — permettre la correction
5. **Limitation de conservation** — durée définie, suppression après
6. **Intégrité et confidentialité** — sécurité (voir `security.md`)
7. **Imputabilité** — pouvoir démontrer la conformité (logs de consentement)

## 3. BASES LÉGALES — Quand peut-on traiter ?

| Base légale | Cas d'usage typique |
|---|---|
| **Consentement** | Newsletter, cookies non essentiels, marketing, profilage |
| **Contrat** | Commande e-commerce, création de compte pour service demandé |
| **Obligation légale** | Facturation (conservation 10 ans), lutte anti-blanchiment |
| **Sauvegarde des intérêts vitaux** | Urgence médicale |
| **Mission d'intérêt public** | Service public |
| **Intérêt légitime** | Sécurité du service, détection de fraude (avec test d'équilibre) |

**Règle :** Chaque traitement doit avoir une base légale documentée. Pour le marketing et les cookies non essentiels, seul le **consentement** est valable.

## 4. CONSENTEMENT — Exigences ePrivacy & RGPD

Le consentement doit être :
- **Libre** — pas de conséquence négative si refus
- **Spécifique** — par finalité
- **Éclairé** — information claire préalable
- **Univoque** — action positive (pas de case pré-cochée)
- **Réversible** — retrait aussi facile que le don

### Implémentation obligatoire d'une bannière cookies

```typescript
// components/cookie-banner.tsx
'use client';
import { useState, useEffect } from 'react';
import { setCookieConsent } from '@/lib/consent';

export function CookieBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const consent = localStorage.getItem('cookie-consent');
    if (!consent) setVisible(true);
  }, []);

  const accept = (categories: ConsentCategories) => {
    setCookieConsent(categories);
    localStorage.setItem('cookie-consent', JSON.stringify(categories));
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div role="dialog" aria-label="Consentement cookies">
      <p>
        Nous utilisons des cookies pour assurer le fonctionnement du site 
        et, avec votre consentement, pour mesurer l'audience et personnaliser 
        votre expérience.
      </p>
      <button onClick={() => accept({ essential: true, analytics: true, marketing: true })}>
        Tout accepter
      </button>
      <button onClick={() => accept({ essential: true, analytics: false, marketing: false })}>
        Refuser les cookies non essentiels
      </button>
      <button onClick={() => router.push('/cookies/configure')}>
        Personnaliser
      </button>
    </div>
  );
}
```

### Règles de la bannière (recommandations CNIL)

- **Position** : bas de page ou bandeau, ne bloquant pas l'accès au contenu
- **Bouton "Refuser"** : aussi visible que "Accepter" (taille, couleur identiques)
- **Pas de case pré-cochée**
- **Pas de consentement implicite** (scroll = refus, pas acceptation)
- **Conservation du consentement** : 13 mois maximum (recommandation CNIL)
- **Re-ask** après expiration
- **Pouvoir retirer** à tout moment via un lien persistant (footer : "Gérer mes cookies")

### Stockage du consentement

Le consentement doit être **tracé** (preuve) :
- Date et heure
- Version de la bannière
- Catégories acceptées
- Hash du contenu de la bannière au moment du consentement

```typescript
// lib/consent.ts
import { cookies } from 'next/headers';

export async function saveConsentProof(categories: ConsentCategories) {
  const proof = {
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    categories,
    bannerHash: 'sha256-of-banner-content',
  };
  
  // Stocker en base pour preuve (article 7.1 RGPD)
  await db.consentLog.create({ data: { userId, ...proof } });
  
  // Cookie fonctionnel (non soumis à consentement car trace la preuve)
  cookies().set('consent-proof', JSON.stringify(proof), {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 13 * 30 * 24 * 60 * 60, // 13 mois
  });
}
```

## 5. COOKIES — Classification

| Type | Exemple | Consentement requis ? |
|---|---|---|
| **Strictement nécessaires** | Session, panier, CSRF, consentement lui-même | NON |
| **Fonctionnels** | Préférences langue, thème | OUI (recommandé CNIL) |
| **Mesure d'audience** | GA4, Matomo, Plausible | OUI (sauf exempté CNIL pour anonymisé) |
| **Publicité** | Meta Pixel, Google Ads | OUI |
| **Tiers** | YouTube, maps, social embeds | OUI |

### Charge conditionnelle des scripts

```typescript
// lib/analytics.ts
export function loadAnalytics() {
  const consent = getConsentFromCookie();
  if (!consent?.analytics) return; // NE PAS charger
  
  // Charger GA4 / Matomo uniquement ici
  const script = document.createElement('script');
  script.src = 'https://www.googletagmanager.com/gtag/js?id=G-XXX';
  script.async = true;
  document.head.appendChild(script);
}

// Hook appelé lors du changement de consentement
export function onConsentChange(categories: ConsentCategories) {
  if (categories.analytics) loadAnalytics();
  else removeAnalytics();
}
```

**Règle absolue :** Aucun script de tracking ne doit être chargé dans `<head>` sans garde de consentement. Vérifie systématiquement le `<Script>` de Next.js et `<script>` HTML.

## 6. DROITS DES PERSONNES — Implémentation

Le RGPD accorde 8 droits. L'application doit pouvoir les exercer :

| Droit | Article | Implémentation |
|---|---|---|
| Information | 13, 14 | Page `/privacy` + bannière cookies |
| Accès | 15 | Page `/account/data` (export JSON) |
| Rectification | 16 | Édition de profil |
| Effacement | 17 | Bouton "Supprimer mon compte" + suppression cascade |
| Limitation | 18 | Bouton "Geler mon compte" |
| Portabilité | 20 | Export JSON / CSV téléchargeable |
| Opposition | 21 | Bouton "Désactiver le marketing" |
| Décision automatisée | 22 | Pas de profilage sans consentement + recours humain |

### Délais

- **Réponse à une demande** : 1 mois maximum (art. 12.3)
- **Confirmation d'effacement** : sans tarder (art. 17.3)
- **Notification de violation** : 72h à la CNIL (art. 33), "sans tarder" aux personnes (art. 34)

### Implémentation du droit à l'oubli

```typescript
// app/api/account/delete/route.ts
export async function DELETE(request: Request) {
  const session = await requireAuth();
  const { password } = await request.json();
  
  // Re-authentification obligatoire
  const user = await db.user.findUnique({ where: { id: session.userId } });
  if (!await bcrypt.compare(password, user.passwordHash)) {
    return Response.json({ error: 'Mot de passe invalide' }, { status: 401 });
  }
  
  // Anonymisation plutôt que suppression (si obligations légales)
  await db.user.update({
    where: { id: session.userId },
    data: {
      email: `deleted-${user.id}@anon.local`,
      name: null,
      passwordHash: null,
      deletedAt: new Date(),
    },
  });
  
  // Suppression des données annexes
  await db.session.deleteMany({ where: { userId: session.userId } });
  await db.auditLog.deleteMany({ where: { userId: session.userId } });
  
  // Invalidation session
  cookies().delete('access_token');
  cookies().delete('refresh_token');
  
  return Response.json({ success: true });
}
```

## 7. POLITIQUE DE CONFIDENTIALITÉ — Obligatoire

Une page `/privacy` est obligatoire. Elle doit contenir :

1. **Identité du responsable de traitement** (entreprise, SIRET, contact DPO)
2. **Finalités** du traitement (pourquoi chaque donnée est collectée)
3. **Base légale** de chaque traitement
4. **Durée de conservation** par type de donnée
5. **Destinataires** (qui a accès — hébergeur, prestataires, sous-traitants)
6. **Transferts hors UE** (avec garanties : clauses contractuelles types, décision d'adéquation)
7. **Droits** des personnes + mode d'exercice
8. **Cookies** utilisés + gestion
9. **Recours** auprès de la CNIL

```tsx
// app/privacy/page.tsx
export default function PrivacyPage() {
  return (
    <main>
      <h1>Politique de confidentialité</h1>
      {/* Sections obligatoires ci-dessus */}
      <section>
        <h2>Responsable du traitement</h2>
        <p>[Nom entreprise], [SIRET], [Adresse]</p>
        <p>Contact DPO : dpo@example.com</p>
      </section>
      {/* ... */}
    </main>
  );
}
```

**Règle :** Si l'application web collecte ne serait-ce qu'un email, la page `/privacy` est obligatoire. Sans elle, l'application ne peut pas être livrée.

## 8. MENTIONS LÉGALES — Obligatoire (Loi pour une République Numérique)

Page `/legal` obligatoire contenant :
- Éditeur (nom, statut juridique, capital, RCS)
- Hébergeur (raison sociale, adresse)
- Directeur de publication
- Contact
- Numéro de TVA intracomunautaire (si applicable)

## 9. NAVIGATION LÉGALE COHÉRENTE — Sitemap, footer, pages

Le RGPD et la Loi pour une République Numérique exigent que les pages légales soient **facilement accessibles**. Cela implique une cohérence stricte entre trois éléments : la page physique, le lien dans le footer, et l'entrée dans le sitemap.

### Triplet obligatoire

Pour chaque page légale (`/privacy`, `/legal`, `/cookies`, `/cgu`, `/cgv`) :

1. **Page physique** — fichier `app/<page>/page.tsx` (ou `pages/<page>.tsx`) existant
2. **Lien footer** — référencé dans le composant footer affiché sur toutes les pages
3. **Entrée sitemap** — listé dans `app/sitemap.ts` (ou `sitemap.xml` statique)

### Anti-patterns interdits

- ❌ Légal en ancre `/#mentions-legales` — pas de page dédiée, contenu non indexable, non deep-linkable
- ❌ URLs incohérentes (`/mentions-legales` dans le footer, `/legal` dans le sitemap)
- ❌ Page légale non listée dans le sitemap (invisible pour les moteurs de recherche)
- ❌ Page légale dans le sitemap mais pas dans le footer (utilisateur ne peut pas y accéder)
- ❌ `robots.txt` qui exclut les pages légales (`Disallow: /privacy`)
- ❌ Page légale sans URL canonique stable

### Implémentation Next.js App Router

```typescript
// app/sitemap.ts
import { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = process.env.NEXT_PUBLIC_SITE_URL!;
  const lastModified = new Date();
  
  return [
    { url: `${baseUrl}/`, lastModified, changeFrequency: 'weekly', priority: 1 },
    { url: `${baseUrl}/privacy`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${baseUrl}/legal`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${baseUrl}/cookies`, lastModified, changeFrequency: 'yearly', priority: 0.3 },
    // ... autres pages
  ];
}
```

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

### URL canonique stable

Chaque page légale doit définir sa canonical pour éviter le duplicate content :

```tsx
// app/privacy/page.tsx
export const metadata = {
  title: 'Politique de confidentialité',
  alternates: {
    canonical: '/privacy',
  },
  robots: { index: true, follow: true },
};
```

### robots.txt — Ne pas exclure les pages légales

```typescript
// app/robots.ts
import { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/' },
    // NE PAS mettre Disallow: /privacy, /legal, /cookies
    sitemap: `${process.env.NEXT_PUBLIC_SITE_URL}/sitemap.xml`,
  };
}
```

### Vérification automatique

À chaque ajout, modification ou suppression d'une page légale, vérifier dans le même commit :
- [ ] Le fichier `app/<page>/page.tsx` existe
- [ ] Le composant footer référence cette URL
- [ ] Le fichier `app/sitemap.ts` liste cette URL
- [ ] L'URL dans le footer == l'URL dans le sitemap
- [ ] La page a une canonical
- [ ] `robots.txt` ne l'exclut pas

## 10. DONNÉES SENSIBLES — Article 9 RGPD

Sont interdites sauf exception (consentement explicite, intérêt public) :

- Origine raciale ou ethnique
- Opinions politiques, religieuses, philosophiques
- Appartenance syndicale
- Données génétiques, biométriques
- Données de santé
- Vie sexuelle ou orientation
- Casier judiciaire

**Règle :** Si l'application demande ce type de donnée, exiger consentement explicite (case à cocher dédiée) + analyse d'impact (AIPD) documentée.

## 11. MINEURS — Règles spécifiques

- **Moins de 15 ans** (France, art. 8 RGPD) : consentement parental obligatoire
- **15-18 ans** : consentement propre, mais mesure de protection renforcée
- **Pas de profilage** à but marketing vers mineurs
- **Pas de publicité comportementale** ciblant les mineurs

## 12. TRANSFERTS HORS UE

Si une donnée perso est envoyée hors UE (ex: AWS us-east, service US) :
1. Vérifier le pays a une décision d'adéquation (Commission UE)
2. Sinon, garanties appropriées : Clauses Contractuelles Types (CCT 2021/914)
3. Documenter dans le registre des traitements

**Vérification typique :** Hébergement Vercel → vérifier région (fra1 pour EU), supabase → région Frankfurt, etc.

```typescript
// next.config.js — forcer région EU
module.exports = {
  // Vercel
  regions: ['fra1'],
};
```

## 13. NOTIFICATION DE VIOLATION — Plan d'urgence

En cas de fuite de données :
1. **Confiner** — révoquer accès/keys compromis
2. **Évaluer** le risque pour les personnes
3. **Notifier la CNIL** dans les 72h via https://www.cnil.fr/fr/notifier-une-violation-de-donnees
4. **Notifier les personnes** si risque élevé (art. 34)
5. **Documenter** (registre des violations, art. 33.5)

L'application doit avoir un endpoint `/api/security/incident` (interne) pour déclencher ce protocole.

## 14. VÉRIFICATIONS AUTOMATIQUES RGPD APPLIQUÉES PAR LE SKILL

À chaque génération de code, vérifier :

- [ ] Tout cookie non essential est précédé d'un check de consentement
- [ ] Tout script de tracking (GA, Meta, etc.) est chargé conditionnellement
- [ ] Toute collecte d'email / nom / téléphone a une mention de finalité
- [ ] Page `/privacy` existe
- [ ] Page `/legal` existe
- [ ] Page `/cookies` (ou gestion dans le footer) existe
- [ ] Bouton "Supprimer mon compte" accessible
- [ ] Bouton "Exporter mes données" accessible
- [ ] Logs ne contiennent pas de données perso sensibles
- [ ] Donnée perso en BDD est chiffrée au repos si sensible
- [ ] Durée de conservation définie (job cron de purge)
- [ ] Hébergement en UE ou garanties documentées
- [ ] Triplet sitemap / footer / pages légales cohérent
- [ ] Pas d'ancre `/#mentions-legales` comme lien légal
- [ ] URL canonique définie sur chaque page légale
- [ ] `robots.txt` n'exclut pas les pages légales
