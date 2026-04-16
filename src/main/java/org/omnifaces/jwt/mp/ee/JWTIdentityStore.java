package org.omnifaces.jwt.mp.ee;

import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

import java.security.Principal;

import org.glassfish.soteria.TokenCredential;
import org.omnifaces.jwt.mp.jwt.JsonWebTokenImpl;

public class JWTIdentityStore implements IdentityStore {

    org.glassfish.soteria.identitystores.JWTIdentityStore soteriaStore;

    public JWTIdentityStore(org.glassfish.soteria.identitystores.JWTIdentityStore soteriaStore) {
        this.soteriaStore = soteriaStore;
    }

    public CredentialValidationResult validate(TokenCredential credential) {
        CredentialValidationResult soteriaResult = soteriaStore.validate(credential);

        Principal callerPrincipal = soteriaResult.getCallerPrincipal();

        if (callerPrincipal instanceof org.glassfish.soteria.identitystores.jwt.JsonWebTokenImpl soteriaTokenImpl) {
            return new CredentialValidationResult(
                    new JsonWebTokenImpl(soteriaTokenImpl.getName(),
                    soteriaTokenImpl.claims()), soteriaResult.getCallerGroups());
        }

        return soteriaResult;

    }
}
