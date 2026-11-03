# continuum-auth

Service d'authentification de Continuum (plan §4.5) : image **Keycloak** à version figée, étendue par le
SPI maison (`continuum-keycloak-spi`) et les thèmes aux couleurs du tenant. Keycloak est un service
**séparé** du backend (§4.3.3).

## Contenu

- `Dockerfile` — part de `quay.io/keycloak/keycloak` (ARG `KEYCLOAK_VERSION`, qui **doit** correspondre à
  `<keycloak.version>` de `../continuum-keycloak-spi/pom.xml`), copie le jar de SPI dans
  `/opt/keycloak/providers/`, copie les thèmes, puis `kc.sh build`.
- `themes/continuum-theme` — thème de la page de connexion (tokens `--ct-*`, §1.6.3).
- `realms/` — export(s) de realm (squelette à compléter : realm `banque-demo`, clients `continuum-app`
  et `continuum-admin`, exigence `acr ≥ 2` côté admin).

## Construire

Le jar de SPI doit être produit d'abord :

```bash
(cd ../continuum-keycloak-spi && mvn -o -q package)
docker build -t continuum-auth .
```

> Image buildée en mode `kc.sh build` (providers + thèmes figés) ; démarrage via `start`. Pour une pile
> locale complète, préférer la simulation (`../Instructions/infra/simulation/`) et `../run.ps1 -Mode full`.

## Références

SPI : `../continuum-keycloak-spi`. Plan : §4.5 (Keycloak + SPI + thèmes). Déploiement :
`../Instructions/docs/exploitation/DEPLOIEMENT.md`.

## Client de service admin (D40)

`realms/continuum-admin-service.fragment.json` : client confidentiel `continuum-admin-service`
(client_credentials uniquement, secret via `KC_ADMIN_SERVICE_SECRET`), compte de service porteur du rôle
realm `continuum-user-admin` (composite `realm-management` : `manage-users` seul, qui couvre lecture et écriture des endpoints utilisateurs).
Usage backend (token via `POST /realms/{realm}/protocol/openid-connect/token`) :
- reset-mfa : `GET /admin/realms/{realm}/users?username=…` puis `GET …/users/{id}/credentials`
  et `DELETE …/users/{id}/credentials/{credId}` pour chaque credential `otp` ;
- close-sessions : `POST /admin/realms/{realm}/users/{id}/logout`.
L'état verrouillé/désactivé est lu côté backend (`platform.user_account`) via `getAccountLoginStatus`
(motif `ACCOUNT_DISABLED`) ; le SPI relaie tout `reason` reçu sans logique métier.

Note: the fragment also carries `scopeMappings` (client `continuum-admin-service` -> role `continuum-user-admin`); without it `fullScopeAllowed:false` strips realm-management roles from the token and every admin call returns 403. Verified on Keycloak 26.3.0 with manage-users only: username lookup 200, credentials list 200, otp credential DELETE 204, users/{id}/logout 204. Keycloak user id = `user_account.id` must equal the Keycloak user UUID (look up by username otherwise).

## Client de synchronisation annuaire

`realms/continuum-directory-sync.fragment.json` : client confidentiel `continuum-directory-sync`
(client_credentials uniquement, secret via `KC_DIRECTORY_SYNC_SECRET`), compte de service porteur du rôle
realm `continuum-directory-sync` (composite `realm-management` : `manage-users` + `view-realm`, avec
`scopeMappings` obligatoire car `fullScopeAllowed:false`). Séparé de `continuum-admin-service` (moindre privilège).
Usage backend (job planifié) :
- résolution du composant par nom : `GET /admin/realms/{realm}/components?type=org.keycloak.storage.UserStorageProvider&name={source_code}`
  (`view-realm` requis, sinon 403) ; `source_code` (`directory_sync_state`) = **nom du composant LDAP** (sim : `ad-banque`) ;
- synchro : `POST /admin/realms/{realm}/user-storage/{id}/sync?action=triggerChangedUsersSync|triggerFullSync`
  (`manage-users` requis) → JSON `{added,updated,removed,failed,status}`.

Vérifié (Keycloak 26.3.0 sim + Samba AD, `./sim.ps1 init-ad`) : lookup par nom 200 ; `triggerChangedUsersSync` 200 ;
`triggerFullSync` 200 (`updated:6`, `failed:2` = utilisateurs locaux `ig.demo`/`dsi.admin` créés par `setup-demo.sh`,
non liés à la fédération : attendu) ; `PUT /admin/realms/{realm}` 403 et `GET …/clients` 403 (pas de sur-privilège).
Sans `view-realm` : lookup par nom 403 (alternative : fournir l'id du composant par configuration).
Secret de sim : `KC_DIRECTORY_SYNC_SECRET=dev-only-directory-sync-secret` (non committé en prod).

## Spike ADR 0014 / D41 — direct grant + OTP et `acr` (2026-11-02, Keycloak 26.3)

`recette/spike-d41-direct-grant-acr.sh` (realm jetable `spike-d41`, aucun realm partagé modifié). Résultat : **non**,
un client confidentiel en *direct grant* + OTP **n'obtient jamais `acr` ≥ 2** en configuration native :
- flux direct grant à conditions *Level of Authentication* (LoA1 mot de passe, LoA2 OTP, `acr.loa.map` `{"1":1,"2":2}`),
  avec `acr_values=2`, `claims` `acr` essentiel, ou `default.acr.values`/`minimum.acr.value` = 2 sur le client → toujours `acr=1` ;
  **danger** : dans ce flux les sous-flux conditionnels sont ignorés en direct grant → jeton délivré avec **mot de passe faux**
  et OTP faux. Ne jamais mettre `conditional-level-of-authentication` dans un flux direct grant ;
- flux direct grant à OTP **toujours requis** : OTP bien exigé (sans OTP / OTP faux → `invalid_grant`), mais `acr=1` ;
- « OTP manquant » et « mot de passe faux » renvoient la même erreur (`invalid_grant`, *Invalid user credentials*) : le BFF ne peut
  pas en déduire qu'un défi OTP est nécessaire (il doit le savoir autrement, ex. credentials via `continuum-admin-service`).
Pistes pour `acr` ≥ 2 en REST : (a) mapper `acr` codé en dur sur un client dont le flux impose l'OTP (acr « par construction »,
fragile : une dérive de config produit un faux `acr`) ; (b) authenticator SPI qui positionne le LoA après OTP réussi ⟨à prototyper⟩.
Sans cela, `/api/admin/**` et signatures restent en redirection (voie C).

## Clients BFF ADR 0014 / D41 (acceptée 2026-11-02)

`realms/continuum-auth-bff.fragment.json` : un client **confidentiel par front**, utilisé **uniquement** par le BFF backend
(`/api/auth/*`) ; les jetons ne quittent jamais le serveur. Aucun mapper `acr` codé en dur ; `acr` réel via le scope `acr`.

| | `continuum-app-bff` | `continuum-admin-bff` |
|---|---|---|
| Secret (env, jamais committé) | `KC_APP_BFF_SECRET` | `KC_ADMIN_BFF_SECRET` |
| Propriétés backend | `continuum.auth.bff.app.client-id/secret` | `continuum.auth.bff.admin.client-id/secret` |
| *Direct grant* (login REST) | oui (flux `direct grant` du realm, OTP si l'utilisateur en a un, `acr=1`) | **non** (`unauthorized_client`) |
| Code + PKCE S256 (repli, SSO, step-up) | oui | oui (seul flux) |
| Callback (même origine, sim) | `http://localhost:4200/api/auth/callback`, `:4203` | `http://localhost:4201/api/auth/callback`, `:4202` |
| `acr` | 1 ; `acr_values=2` → OTP → 2 | toujours 2 (`default.acr.values`/`minimum.acr.value` = 2) |
| Audience | `continuum-app` | `continuum-admin` |

Mappers communs : `tenant_id`, `continuum_user_id` ; scopes `basic`/`acr`/`profile`/`email`, `fullScopeAllowed:false` (pas de rôles).
Flux navigateur `continuum-browser-loa` (surcharge par client, les bindings du realm ne changent pas) : cookie OU
[LoA1 mot de passe | LoA2 OTP] ; `loa-max-age` 36000 s (LoA1) / 300 s (LoA2) = valeurs techniques ⟨à valider⟩ avec le pack.
Les origines de prod viennent du déploiement (le fragment ne porte que celles de la simulation).

**Fusion dans un export de realm** : `python -I realms/merge-fragments.py REALM.json realms/<fragment>.json… [-o OUT]`
(idempotent, remplace par clé naturelle `clientId`/`alias`/`username`/`name`/`client`, conserve UTF-8, indentation 2 et fins de ligne).
Vérifié : re-fusionner `continuum-admin-service` + `continuum-directory-sync` dans `banque-demo-realm.json` → fichier identique octet pour octet.

**Vérification** : `python -I recette/verify-auth-bff-fragment.py [REALM.json]` importe `banque-demo-realm.json` **fusionné**
avec le fragment dans un realm jetable `verify-d41-bff` (Keycloak sim local) et pilote les vraies pages de login :
direct grant (OTP exigé/refusé, claims, `acr=1`), Code+PKCE (sans PKCE refusé, `code_verifier`/secret faux refusés,
redirect_uri inconnue 400, rejeu du code refusé), step-up `acr_values=2` dans la même session → OTP seul → `acr=2`,
admin : direct grant refusé, mot de passe + OTP → `acr=2`/aud `continuum-admin`, utilisateur sans OTP → page d'enrôlement TOTP.
2026-11-02, Keycloak 26.3 : **37/37 OK**. Mot de passe admin du Keycloak : `KC_ADMIN_PASSWORD`.

**Provisionnement d'un realm vivant** (sans ré-import) : `python -I recette/setup-auth-bff-clients.py [--verify-only] REALM…`
crée/aligne via l'API admin le flux `continuum-browser-loa` et les deux clients **exactement** comme le fragment (seule source,
rien n'est redéclaré dans le script) ; idempotent, un flux dérivé est reconstruit. Secrets `KC_APP_BFF_SECRET` /
`KC_ADMIN_BFF_SECRET` lus dans l'environnement, sinon `recette/.env.local`, sinon générés et ajoutés à `recette/.env.local`
(jamais affichés). Vérifie ensuite le résultat vivant : structure = fragment, secret accepté / faux secret refusé, admin sans
direct grant, `client_credentials` refusé, PKCE obligatoire, redirect_uri inconnue refusée et, si `VERIFY_USER`/`VERIFY_PASSWORD`
(utilisateur sans OTP), un vrai direct grant `continuum-app-bff` (`acr=1`, aud `continuum-app`, `tenant_id`/`continuum_user_id`).
2026-11-03, Keycloak sim `:8180` : `banque-demo` (secrets = valeurs dev de `.env.example` de la simulation, `ig.demo`) **29/29 OK** ;
`recette` (secrets générés dans `recette/.env.local`, `dsi.admin`) **29/29 OK** ; ré-exécution sans changement ; dérive
(OTP passé à `DISABLED`) détectée puis flux reconstruit. NB : Keycloak ignore une map d'overrides vide, un override se retire par valeur `""`.

## Recette : rôles des clients de service du backend

`recette/setup-recette-backend-roles.sh` (idempotent, `KC_ADMIN_PASSWORD` requis) provisionne dans le realm
`recette` exactement les deux fragments ci-dessus : `continuum-admin-service` (`continuum-user-admin` = {manage-users})
et `continuum-directory-sync` (`continuum-directory-sync` = {manage-users, view-realm}), confidentiels,
client_credentials seul, `fullScopeAllowed:false` + scope mapping. Il supprime l'ancien client lecture seule
`continuum-backend` (remplacé, validé par le tech-lead le 2026-11-02). Les secrets vont dans `recette/.env.local`
(non versionné) ; `KC_DIRECTORY_SYNC_SECRET` et `CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET` y reçoivent la même valeur.
Côté backend : `CONTINUUM_KC_ADMIN_BASE_URL` (vide = 503), `CONTINUUM_KC_ADMIN_REALM=recette`,
`CONTINUUM_DIRECTORY_SYNC_CLIENT_ID=continuum-directory-sync` (+ `..._ENABLED`/`..._SOURCE` si la synchro doit tourner).
Contrôles en direct : `recette/verify-recette-backend-roles.sh` (rôles du jeton, lookup/credentials/logout,
components, manage-realm et liste des clients refusés en 403).

## Socle de sécurité du realm : OTP + anti-force brute (ADR 0014 §5)

`realms/continuum-realm-security.fragment.json` : détection native de force brute (verrouillage **temporaire** :
`failureFactor` 5, attente croissante 60 s → 900 s max, fenêtre 12 h, quick-login 1 s / 60 s) et action requise
`CONFIGURE_TOTP` **activée** mais **pas action par défaut** (l'enrôlement MFA suit la politique du tenant). Valeurs
de sim/pack ⟨à valider⟩, identiques à `banque-demo-realm.json` ; la cible = paramètres en base.
Appliqué aux realms vivants par `recette/setup-realm-security.py` (idempotent, `--verify-only` pour contrôler) — pas
par `merge-fragments.py` : une liste `requiredActions` partielle dans un import supprimerait les actions par défaut
de Keycloak (l'import par défaut active déjà `CONFIGURE_TOTP`).

```bash
KC_ADMIN_PASSWORD=... python -I recette/setup-realm-security.py banque-demo recette
```

Vérification (utilisateur jetable, mot de passe aléatoire jamais affiché, supprimé en fin) : réglages du realm et de
l'action relus ; utilisateur avec `CONFIGURE_TOTP` + bon mot de passe → 400 *Account is not fully set up* ; 4 échecs
espacés (> quick-login) → encore actif, 5ᵉ → `attack-detection` `disabled:true` et bon mot de passe → 401
`invalid_grant` ; verrou levé → 200. Vérifié 2026-11-03 sur Keycloak 26.3.5 jetable (realms `banque-demo` importé et
`recette` vierge : avant application, `recette` = force brute désactivée, `failureFactor` 30).
