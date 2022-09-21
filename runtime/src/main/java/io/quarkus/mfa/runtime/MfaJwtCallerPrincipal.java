package io.quarkus.mfa.runtime;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;

public class MfaJwtCallerPrincipal extends DefaultJWTCallerPrincipal {

    public MfaJwtCallerPrincipal(JwtClaims claimsSet) {
        super(claimsSet);
    }

    @Override
    public String getName() {
        return getClaim(Claims.sub.name());
    }

}
