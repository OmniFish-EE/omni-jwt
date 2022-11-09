/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) [2022-2022] OmniFaces and/or its affiliates. All rights reserved.
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
    requires jakarta.security;
    requires microprofile.jwt.auth.api;
    requires jakarta.ws.rs;
    requires com.nimbusds.jose.jwt;

    exports org.omnifaces.jwt.cdi;
    exports org.omnifaces.jwt.eesecurity;
    exports org.omnifaces.jwt.jaxrs;
    exports org.omnifaces.jwt.jwt;
    exports org.omnifaces.jwt.servlet;

    // This is needed for CDI extensions that use non-public observer methods
    opens org.omnifaces.jwt.cdi to weld.core.impl;

    provides jakarta.enterprise.inject.spi.Extension with org.omnifaces.jwt.cdi.CdiExtension;
    provides jakarta.servlet.ServletContainerInitializer with org.omnifaces.jwt.servlet.RolesDeclarationInitializer;
    provides jakarta.ws.rs.container.DynamicFeature with org.omnifaces.jwt.jaxrs.RolesAllowedDynamicFeature;
}
