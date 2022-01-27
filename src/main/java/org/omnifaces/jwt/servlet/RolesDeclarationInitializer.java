/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) [2017-2021] Payara Foundation and/or its affiliates. All rights reserved.
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
package org.omnifaces.jwt.servlet;

import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;

import java.util.Set;
import java.util.logging.Logger;

import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

import org.omnifaces.jwt.cdi.CdiExtension;

/**
 * This servlet container initializer checks if CDI is active and if so obtains
 * the JWT CDI extension to fetch the collected roles from, which are then declared to the
 * Servlet container.
 *
 *  <p>
 *  Declaring roles is a requirement of Java EE and Payara specifically enforces this. I.e. roles
 *  that aren't declared don't work.
 *
 * @author Arjan Tijms
 */
public class RolesDeclarationInitializer implements ServletContainerInitializer {

    private static final Logger logger =  Logger.getLogger(RolesDeclarationInitializer.class.getName());

    @Override
    public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {

        Set<String> roles = null;
        boolean addJWTAuthenticationMechanism = false;

        try {
            CDI<Object> cdi = CDI.current();

            if (cdi != null) {
                Instance<CdiExtension> extensionInstance = cdi.select(CdiExtension.class);

                if (extensionInstance != null && !extensionInstance.isUnsatisfied() && !extensionInstance.isAmbiguous()) {
                    CdiExtension cdiExtension = extensionInstance.get();

                    if (cdiExtension != null) {
                        roles = cdiExtension.getRoles();
                        addJWTAuthenticationMechanism = cdiExtension.isAddJWTAuthenticationMechanism();
                    }
                }
            }
        } catch (Exception e) {
            logger.log(FINEST, "Exception trying to use CDI:", e);
        }

        if (roles == null) {
            logger.log(FINEST, "CDI not available for context " +  ctx.getContextPath());
            return;
        }

        if (!addJWTAuthenticationMechanism) {
            return; // JWT authentication mechanism not installed, don't process the roles for Payara 4
        }

        if (logger.isLoggable(INFO)) {
            String version = getClass().getPackage().getImplementationVersion();
            logger.log(INFO, "Initializing MP-JWT {0} for context ''{1}''", new Object[]{version, ctx.getContextPath()});
        }

        ctx.declareRoles(roles.toArray(new String[0]));
    }

}
