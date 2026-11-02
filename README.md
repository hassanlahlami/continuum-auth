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
