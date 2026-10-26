# Service d'authentification separe (plan §4.5) : Keycloak a version figee,
# etendu par le jar de SPI maison et les themes.
#
# Squelette — a completer quand continuum-keycloak-spi produit son jar.
# La version DOIT correspondre a <keycloak.version> de ../continuum-keycloak-spi/pom.xml.

ARG KEYCLOAK_VERSION=26.3.0
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

# SPI maison (AuthenticationFlow, mappers, event listeners…)
COPY ../continuum-keycloak-spi/target/continuum-keycloak-spi.jar /opt/keycloak/providers/

# Themes (page de connexion aux couleurs du tenant, §1.6.3)
COPY themes/ /opt/keycloak/themes/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
