/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2017-2021 Payara Foundation and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://github.com/payara/Payara/blob/master/LICENSE.txt
 * See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * The Payara Foundation designates this particular file as subject to the "Classpath"
 * exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
// Portions Copyright 2019, 2020 OmniFaces
package org.omnifaces.jwt.mp.cdi;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.context.SessionScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.AfterBeanDiscovery;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.enterprise.inject.spi.DeploymentException;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.enterprise.inject.spi.ProcessBean;
import jakarta.enterprise.inject.spi.ProcessInjectionTarget;
import jakarta.json.JsonArray;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.identitystore.IdentityStore;

import java.lang.annotation.Annotation;
import java.security.Principal;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import org.eclipse.microprofile.auth.LoginConfig;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.glassfish.soteria.identitystores.JWTIdentityStore;
import org.glassfish.soteria.identitystores.jwt.JWTConfiguration;
import org.glassfish.soteria.mechanisms.JWTAuthenticationMechanism;
import org.omnifaces.jwt.mp.jwt.ClaimAnnotationLiteral;
import org.omnifaces.jwt.mp.jwt.ClaimValueImpl;
import org.omnifaces.jwt.mp.jwt.JWTInjectableType;
import org.omnifaces.jwt.mp.jwt.JsonWebTokenImpl;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toSet;
import static org.eclipse.microprofile.jwt.Claims.UNKNOWN;
import static org.eclipse.microprofile.jwt.config.Names.AUDIENCES;
import static org.eclipse.microprofile.jwt.config.Names.CLOCK_SKEW;
import static org.eclipse.microprofile.jwt.config.Names.DECRYPTOR_KEY_ALGORITHM;
import static org.eclipse.microprofile.jwt.config.Names.DECRYPTOR_KEY_LOCATION;
import static org.eclipse.microprofile.jwt.config.Names.ISSUER;
import static org.eclipse.microprofile.jwt.config.Names.TOKEN_AGE;
import static org.eclipse.microprofile.jwt.config.Names.TOKEN_COOKIE;
import static org.eclipse.microprofile.jwt.config.Names.TOKEN_HEADER;
import static org.eclipse.microprofile.jwt.config.Names.VERIFIER_PUBLIC_KEY;
import static org.eclipse.microprofile.jwt.config.Names.VERIFIER_PUBLIC_KEY_LOCATION;

/**
 * This CDI extension installs the {@link JWTAuthenticationMechanism} and related {@link JWTIdentityStore}
 * when the <code>LoginConfig</code> annotation is encountered (MP-JWT 1.0 5).
 *
 * <p>
 * Additionally this extension checks that injection of claims are in the right scope (non-transitively, 7.1.3).
 *
 * @author Arjan Tijms
 */
public class CdiExtension implements Extension {

    private final static JsonWebTokenImpl emptyJsonWebToken = new JsonWebTokenImpl(null, emptyMap());

    /**
     * Tracks whether a LoginConfig annotation has been encountered and thus
     * a mechanism needs to be installed.
     */
    private boolean addJWTAuthenticationMechanism;

    /**
     * This method tries to find the LoginConfig annotation and if does flags that fact.
     *
     */
    public <T> void findLoginConfigAnnotation(@Observes ProcessBean<T> event, BeanManager beanManager) {
        LoginConfig loginConfig = event.getAnnotated().getAnnotation(LoginConfig.class);
        if (loginConfig != null && loginConfig.authMethod().equals("MP-JWT")) {
            addJWTAuthenticationMechanism = true;
        }
    }

    public <T> void checkInjectIntoRightScope(@Observes ProcessInjectionTarget<T> event, BeanManager beanManager) {
        for (InjectionPoint injectionPoint : event.getInjectionTarget().getInjectionPoints()) {
            Claim claim = hasClaim(injectionPoint);
            if (claim != null) {

                // MP-JWT 1.0 7.1.3.

                Bean<?> bean = injectionPoint.getBean();

                Class<?> scope = bean != null ? injectionPoint.getBean().getScope() : null;

                if (scope != null && scope.equals(SessionScoped.class)) {
                    throw new DeploymentException(
                        "Can't inject using qualifier " + Claim.class + " in a target with scope " + scope);
                }

                if (!claim.value().equals("") && claim.standard() != UNKNOWN && !claim.value().equals(claim.standard().name())) {
                    throw new DeploymentException(
                        "Claim value " + claim.value() + " should be equal to claim standard " + claim.standard().name() +
                        " or one of those should be left at their default value");
                }

            }

        }
    }

    public void installMechanismIfNeeded(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        if (addJWTAuthenticationMechanism) {
            validateConfigValue();
            installAuthenticationMechanism(afterBeanDiscovery, beanManager);
        }
    }

    public static void installAuthenticationMechanism(AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        JWTConfiguration jwtConfiguration = getJWTConfiguration();

        afterBeanDiscovery.addBean()
                .scope(ApplicationScoped.class)
                .beanClass(IdentityStore.class)
                .types(Object.class, IdentityStore.class, org.omnifaces.jwt.mp.ee.JWTIdentityStore.class)
                .id("store " + LoginConfig.class)
                .createWith(e -> new org.omnifaces.jwt.mp.ee.JWTIdentityStore(new JWTIdentityStore(jwtConfiguration)));

        afterBeanDiscovery.addBean()
                .scope(ApplicationScoped.class)
                .beanClass(HttpAuthenticationMechanism.class)
                .types(Object.class, HttpAuthenticationMechanism.class, JWTAuthenticationMechanism.class)
                .id("mechanism " + LoginConfig.class)
                .createWith(e -> new JWTAuthenticationMechanism(jwtConfiguration));

        // MP-JWT 1.0 7.1.1. Injection of JsonWebToken
        afterBeanDiscovery.addBean()
                .scope(RequestScoped.class)
                .beanClass(JsonWebToken.class)
                .types(Object.class, JsonWebToken.class)
                .id("token " + LoginConfig.class)
                .createWith(e -> getJsonWebToken());

        // MP-JWT 1.0 7.1.2
        for (JWTInjectableType injectableType : computeTypes()) {

            // Add a new Bean<T>/Dynamic producer for each type that 7.1.2 asks us to support.
            afterBeanDiscovery.addBean()
                    .scope(Dependent.class)
                    .beanClass(CdiExtension.class)
                    .types(injectableType.getFullType())
                    .qualifiers(new ClaimAnnotationLiteral())
                    .id("claim for " + injectableType.getFullType())
                    .createWith(creationalContext -> {
                        // Get the claimName from the injection point
                        String claimName =
                            getClaimName(
                                getQualifier(
                                    beanManager.createInstance()
                                               .select(InjectionPoint.class)
                                               .get(),
                                    Claim.class));

                        Function<String, Object> claimValueSupplier = (String claimNameParam) -> {
                            return loadClaimObject(injectableType, claimNameParam);
                        };

                        if (injectableType.isClaimValue()) {
                            // If the target type has a ClaimValue in it, wrap the converted value
                            // into a ClaimValue, e.g. ClaimValue<Long> or ClaimValue<Optional<Long>>
                            return new ClaimValueImpl<>(claimName, claimValueSupplier);
                        }

                        // Otherwise simply return the value
                        return claimValueSupplier.apply(claimName);
                    });
        }
    }

    public static Object loadClaimObject(JWTInjectableType injectableType, String claimNameParam) {
        // Obtain the raw named value from the request scoped JsonWebToken's embedded claims and
        // convert it according to the target type for which this Bean<T> was created.
        Object claimObj = injectableType.convert(
                getJsonWebToken().claims()
                        .get(claimNameParam));

        // If the target type has an Optional in it, wrap the converted value
        // into an Optional. I.e. Optional<Long> or ClaimValue<Optional<Long>>
        if (injectableType.isOptional()) {
            claimObj = Optional.ofNullable(claimObj);
        }
        return claimObj;
    }

    public static Set<JWTInjectableType> computeTypes() {
        Set<JWTInjectableType> baseTypes = new HashSet<>(asList(
                new JWTInjectableType(String.class),
                new JWTInjectableType(new ParameterizedTypeImpl(Set.class, String.class), Set.class),
                new JWTInjectableType(Long.class),
                new JWTInjectableType(Boolean.class),
                new JWTInjectableType(JsonString.class),
                new JWTInjectableType(JsonNumber.class),
                new JWTInjectableType(JsonStructure.class),
                new JWTInjectableType(JsonArray.class),
                new JWTInjectableType(JsonObject.class),
                new JWTInjectableType(JsonValue.class)));

        Set<JWTInjectableType> optionalTypes = new HashSet<>(baseTypes);
        optionalTypes.addAll(
                baseTypes.stream()
                        .map(t -> new JWTInjectableType(new ParameterizedTypeImpl(Optional.class, t.getFullType()), t))
                        .collect(toSet()));

        Set<JWTInjectableType> claimValueTypes = new HashSet<>(optionalTypes);
        claimValueTypes.addAll(
                optionalTypes.stream()
                        .map(t -> new JWTInjectableType(new ParameterizedTypeImpl(ClaimValue.class, t.getFullType()), t))
                        .collect(toSet()));

        return claimValueTypes;
    }

    @SuppressWarnings("unchecked")
    public static <T> Bean<T> resolve(BeanManager beanManager, Class<T> beanClass, Annotation... qualifiers) {
        Set<Bean<?>> beans = beanManager.getBeans(beanClass, qualifiers);

        for (Bean<?> bean : beans) {
            if (bean.getBeanClass() == beanClass) {
                return (Bean<T>) beanManager.resolve(Collections.<Bean<?>>singleton(bean));
            }
        }

        Bean<T> bean = (Bean<T>) beanManager.resolve(beans);

        if (bean == null && beanClass.getSuperclass() != Object.class) {
            return (Bean<T>) resolve(beanManager, beanClass.getSuperclass(), qualifiers);
        } else {
            return bean;
        }
    }

    public static <A extends Annotation> A getQualifier(InjectionPoint injectionPoint, Class<A> qualifierClass) {
        for (Annotation annotation : injectionPoint.getQualifiers()) {
            if (qualifierClass.isAssignableFrom(annotation.getClass())) {
                return qualifierClass.cast(annotation);
            }
        }

        return null;
    }

    public static JsonWebTokenImpl getJsonWebToken() {
        SecurityContext context = CDI.current().select(SecurityContext.class).get();

        Principal principal = context.getCallerPrincipal();
        if (principal instanceof JsonWebTokenImpl jsonWebTokenImpl) {
            return jsonWebTokenImpl;
        }

        if (principal instanceof org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl soteriaTokenImpl) {
            return new JsonWebTokenImpl(soteriaTokenImpl.getName(), soteriaTokenImpl.claims());
        }

        Set<org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl> principals = context.getPrincipalsByType(org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl.class);
        if (!principals.isEmpty()) {
            org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl soteriaTokenImpl = principals.iterator().next();
            return new JsonWebTokenImpl(soteriaTokenImpl.getName(), soteriaTokenImpl.claims());
        }

        return emptyJsonWebToken;
    }

    public static String getClaimName(Claim claim) {
        if (claim.value().equals("")) {
            return claim.standard().name();
        }

        return claim.value();
    }

    public static final String CONFIG_TOKEN_HEADER_AUTHORIZATION = "Authorization";
    public static final String CONFIG_TOKEN_HEADER_COOKIE = "Cookie";

    public static JWTConfiguration getJWTConfiguration() {
        Config config = ConfigProvider.getConfig();

        String configJwtTokenHeader = config.getOptionalValue(TOKEN_HEADER, String.class).orElse(CONFIG_TOKEN_HEADER_AUTHORIZATION);
        String configJwtTokenCookie = config.getOptionalValue(TOKEN_COOKIE, String.class).orElse("Bearer");

        String acceptedIssuer = config.getValue(ISSUER, String.class);
        List<String> allowedAudience = config.getOptionalValue(AUDIENCES, String.class).map(str -> asList(str.split(","))).orElse(emptyList());

        String publicKey = config.getOptionalValue(VERIFIER_PUBLIC_KEY, String.class).orElse("");
        String publicKeyLocation = config.getOptionalValue(VERIFIER_PUBLIC_KEY_LOCATION, String.class).orElse("/publicKey.pem");
        String decryptKeyLocation = config.getOptionalValue(DECRYPTOR_KEY_LOCATION, String.class).orElse("/privateKey.pem");

        long tokenAge = config.getOptionalValue(TOKEN_AGE, Long.class).orElse(Long.MAX_VALUE);
        long clockSkew = config.getOptionalValue(CLOCK_SKEW, Long.class).orElse(0l);

        Duration keyCacheTTL = config.getOptionalValue("publicKey.cache.ttl", Duration.class).orElse(Duration.ofMinutes(5));

        boolean enableNamespace = config.getOptionalValue("enable.namespace", Boolean.class).orElse(false);
        String customNamespace = config.getOptionalValue("custom.namespace", String.class).orElse("foo://");
        boolean disableTypeVerification = config.getOptionalValue("disable.type.verification", Boolean.class).orElse(false);

        boolean isEncryptionRequired = config.getOptionalValue(DECRYPTOR_KEY_LOCATION, String.class).isPresent();

        String keyAlgorithm = config.getOptionalValue(DECRYPTOR_KEY_ALGORITHM, String.class).orElse("");

        return new JWTConfiguration(
                // Authentication mechanism
                configJwtTokenHeader,
                configJwtTokenCookie,

                // Identity store
                acceptedIssuer,
                allowedAudience,
                publicKey,
                publicKeyLocation,
                decryptKeyLocation,
                keyAlgorithm,
                tokenAge,
                clockSkew,
                keyCacheTTL,
                enableNamespace,
                customNamespace,
                disableTypeVerification,
                isEncryptionRequired);

    }

    private void validateConfigValue() {
        Config config = ConfigProvider.getConfig();

        if (config.getOptionalValue(VERIFIER_PUBLIC_KEY, String.class).isPresent()
                && config.getOptionalValue(VERIFIER_PUBLIC_KEY_LOCATION, String.class).isPresent()) {
            throw new DeploymentException(
                    "Both properties mp.jwt.verify.publickey and mp.jwt.verify.publickey.location must not be defined"
            );
        }

        String configJwtTokenHeader = config.getOptionalValue(TOKEN_HEADER, String.class).orElse(CONFIG_TOKEN_HEADER_AUTHORIZATION);

        if (!CONFIG_TOKEN_HEADER_AUTHORIZATION.equals(configJwtTokenHeader) && !CONFIG_TOKEN_HEADER_COOKIE.equals(configJwtTokenHeader)) {
            throw new DeploymentException(
                "Property " + TOKEN_HEADER + " can only be " +
                 CONFIG_TOKEN_HEADER_AUTHORIZATION + " or " + CONFIG_TOKEN_HEADER_COOKIE +
                 ", but is " + configJwtTokenHeader);
        }

    }

    public boolean isAddJWTAuthenticationMechanism() {
        return addJWTAuthenticationMechanism;
    }

    private static Claim hasClaim(InjectionPoint injectionPoint) {
        for (Annotation qualifier : injectionPoint.getQualifiers()) {
            if (qualifier.annotationType().equals(Claim.class)) {
                return (Claim) qualifier;
            }
        }

        return null;
    }

}
