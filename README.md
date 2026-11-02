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

`realms/continuum-auth-bff.fragment.json` (**brouillon**, non fusionné dans un export de realm) : client confidentiel
`continuum-auth-bff`, *direct grant* seul (pas de flux navigateur, pas de compte de service), secret `KC_AUTH_BFF_SECRET`,
scopes `basic`/`acr`/`profile`/`email`, mappers `tenant_id`/`continuum_user_id`, aucun mapper `acr` codé en dur ; flux direct grant
intégré du realm (OTP exigé si l'utilisateur en a un). Vérifié par `recette/verify-auth-bff-fragment.sh` (realm jetable `spike-d41-bff`).
Mapper d'audience à convenir avec backend ⟨à valider⟩.
