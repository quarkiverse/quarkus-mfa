package io.quarkus.mfa.runtime;

import javax.inject.Singleton;

import org.jose4j.jwt.MalformedClaimException;

import io.quarkus.arc.Unremovable;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * MFA IdentityProvider
 */
//IdentityProvider is ignored if annotated with @DefaultBean because there other default IdentityProvider implementations available. Overriding implementations will need to use the @Alternative/@Priority combination.
@Unremovable
@Singleton
public class MfaIdentityProvider implements IdentityProvider<MfaAuthenticationRequest> {

    @Override
    public Class<MfaAuthenticationRequest> getRequestType() {
        return MfaAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(MfaAuthenticationRequest request, AuthenticationRequestContext context) {
        return Uni.createFrom().item(() -> {

            try {
                QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder();
                builder.setPrincipal(new QuarkusPrincipal(request.getClaims().getSubject()));
                request.getClaims().getClaimNames()
                        .forEach(name -> builder.addAttribute(name, request.getClaims().getClaimValue(name)));
                return builder.build();
            } catch (MalformedClaimException e) {
                return null;
            }

        });

    }

}
