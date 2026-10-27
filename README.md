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
realm `continuum-user-admin` (composite `realm-management` : `view-users` + `manage-users`).
Usage backend (token via `POST /realms/{realm}/protocol/openid-connect/token`) :
- reset-mfa : `GET /admin/realms/{realm}/users?username=…` puis `GET …/users/{id}/credentials`
  et `DELETE …/users/{id}/credentials/{credId}` pour chaque credential `otp` ;
- close-sessions : `POST /admin/realms/{realm}/users/{id}/logout`.
L'état verrouillé/désactivé est lu côté backend (`platform.user_account`) via `getAccountLoginStatus`
(motif `ACCOUNT_DISABLED`) ; le SPI relaie tout `reason` reçu sans logique métier.

Note: the fragment also carries `scopeMappings` (client `continuum-admin-service` -> role `continuum-user-admin`); without it `fullScopeAllowed:false` strips realm-management roles from the token and every admin call returns 403. Verified on Keycloak 26.3.0: credentials list 200, users/{id}/logout 204. Keycloak user id = `user_account.id` must equal the Keycloak user UUID (look up by username otherwise).
