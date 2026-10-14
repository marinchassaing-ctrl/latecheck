# LateCheck

Vente de départs tardifs pour locations courte durée. Node 22.13+, aucune dépendance npm.
Paiements : **Stripe Connect Express**, commission LateCheck de 10 % prélevée automatiquement.

## Démarrer en local (mode test Stripe)

1. Sur dashboard.stripe.com, en **mode test**, activez **Connect** (Paramètres > Connect), choisissez « Plateforme », pays France.
2. Copiez la configuration :
   ```bash
   cp .env.example .env
   ```
   Renseignez `STRIPE_SECRET_KEY` (sk_test_…) et `ADMIN_EMAIL`.
3. Installez la CLI Stripe (https://docs.stripe.com/stripe-cli), puis dans un premier terminal :
   ```bash
   stripe login
   npm run stripe:listen
   ```
   Copiez le `whsec_…` affiché dans `STRIPE_WEBHOOK_SECRET` du fichier `.env`.
4. Dans un second terminal :
   ```bash
   npm start
   ```
   Ouvrez http://localhost:3000.

### Scénario de test
1. « Configurer le compte administrateur » avec l'e-mail `ADMIN_EMAIL`, puis déconnexion.
2. Créez un compte hôte → **Mon compte → Connecter mon compte Stripe**.
   Dans l'onboarding test, utilisez les données de test : téléphone `000 000 0000`, code SMS `000000`, IBAN `FR1420041010050500013M02606`.
3. Ajoutez un logement, réglez les tarifs, ouvrez la page voyageur depuis le QR code.
4. Demandez +2 h, acceptez côté hôte, payez avec `4242 4242 4242 4242` (refus : `4000 0000 0000 0002`).
5. Revenus hôte et commission admin se mettent à jour à réception du webhook.

## Comment l'argent circule

Pour un départ tardif à 10 € (estimation de frais par défaut : 1,5 % + 0,25 €) :

| | Montant |
|---|---|
| Payé par le voyageur | 10,00 € |
| Commission LateCheck (10 %) | 1,00 € |
| Frais de paiement facturés à l'hôte | 0,40 € |
| **Versé à l'hôte** | **8,60 €** |

- Paiement **Stripe Checkout** (carte, Apple Pay, Google Pay) en *destination charge* : l'argent arrive sur le compte Stripe de l'hôte, `application_fee_amount` (commission + frais) reste à LateCheck.
- Stripe facture ses frais réels à LateCheck ; l'écart avec l'estimation est visible dans **Admin → Mes revenus**.
- Une commission n'est comptée qu'après le webhook `checkout.session.completed`. Webhooks vérifiés par signature et dédoublonnés.
- Remboursement : client remboursé intégralement, virement à l'hôte et commission annulés. Stripe ne restitue pas ses frais (perte visible côté admin).
- Aucune donnée bancaire n'est stockée par LateCheck : l'hôte saisit son RIB chez Stripe.

## Mise en production

1. Hébergez sur un service avec disque persistant (Render, Railway, Fly.io, VPS). La base SQLite doit être sur un volume persistant.
2. Variables : `APP_URL=https://votre-domaine.fr`, clé **live** `sk_live_…`.
3. Stripe > Développeurs > Webhooks, URL `https://votre-domaine.fr/api/stripe/webhook` :
   - endpoint **Votre compte** : `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.expired`, `payment_intent.payment_failed`, `charge.refunded` → secret dans `STRIPE_WEBHOOK_SECRET`
   - endpoint **Comptes connectés** : `account.updated` → secret dans `STRIPE_CONNECT_WEBHOOK_SECRET`
4. Apple Pay : Paramètres > Moyens de paiement > Apple Pay, enregistrez votre domaine.
5. Complétez le profil de plateforme Connect (nom, logo, conditions) avant de passer en live.
