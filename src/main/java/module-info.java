

/**
 * CDI extension for microprofile jwt implementation.
 *
 */
module org.omnifaces.jwt {
    requires java.logging;

    requires jakarta.cdi;
    requires jakarta.inject;
    requires jakarta.servlet;
    requires jakarta.annotation;

    requires transitive microprofile.config.api;
    requires jakarta.json;
    requires jakarta.security.enterprise.api;
    requires microprofile.jwt.auth.api;
    requires jakarta.ws.rs;
    requires com.nimbusds.jose.jwt;

    exports org.omnifaces.jwt.cdi;
    exports org.omnifaces.jwt.eesecurity;
    exports org.omnifaces.jwt.jaxrs;
    exports org.omnifaces.jwt.jwt;
    exports org.omnifaces.jwt.servlet;

    // this is needed for CDI extensions that use non-public observer methods
    opens org.omnifaces.jwt.cdi to weld.core.impl;

    provides jakarta.enterprise.inject.spi.Extension with org.omnifaces.jwt.cdi.CdiExtension;
    provides jakarta.servlet.ServletContainerInitializer with org.omnifaces.jwt.servlet.RolesDeclarationInitializer;
    provides jakarta.ws.rs.container.DynamicFeature with org.omnifaces.jwt.jaxrs.RolesAllowedDynamicFeature;
}
