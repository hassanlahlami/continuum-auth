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
