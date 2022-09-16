package io.quarkus.mfa.runtime;

import org.jose4j.jwt.JwtClaims;

import io.quarkus.security.identity.request.BaseAuthenticationRequest;

public class MfaAuthenticationRequest extends BaseAuthenticationRequest {
    private JwtClaims claims;

    public MfaAuthenticationRequest(JwtClaims claims) {
        this.claims = claims;
    }

    public JwtClaims getClaims() {
        return claims;
    }
}
