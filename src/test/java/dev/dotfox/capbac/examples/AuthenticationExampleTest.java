package dev.dotfox.capbac.examples;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.capbac.AttenuationChecker;
import dev.dotfox.capbac.CapBAC;
import dev.dotfox.capbac.CapBACCertificate;
import dev.dotfox.capbac.CapBACInvocation;
import dev.dotfox.capbac.CapBACScheme;
import dev.dotfox.capbac.Capability;
import dev.dotfox.capbac.CapabilityCodec;
import dev.dotfox.capbac.Principal;
import dev.dotfox.capbac.PrincipalId;
import dev.dotfox.capbac.Resolver;
import dev.dotfox.capbac.TrustChecker;

/**
 * Demonstrates a user registration and API authentication flow using CapBAC.
 *
 * A user proves ownership of a key pair (self-issued cert), a service grants
 * API permissions, and the user can delegate narrower scopes to bots.
 * Removing a key from the resolver instantly revokes all derived access.
 */
public class AuthenticationExampleTest {

    // -- Domain types --

    static final class AuthCapability implements Capability {
        private final String permission;

        AuthCapability(String permission) {
            this.permission = Objects.requireNonNull(permission);
        }

        String getPermission() { return permission; }

        @Override
        public byte[] toBytes() {
            return permission.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof AuthCapability that && Objects.equals(permission, that.permission));
        }

        @Override
        public int hashCode() { return Objects.hash(permission); }
    }

    static final CapabilityCodec<AuthCapability> CODEC =
            bytes -> new AuthCapability(new String(bytes, StandardCharsets.UTF_8));

    // Attenuation: child permission must start with parent permission (prefix-based narrowing)
    static final AttenuationChecker<AuthCapability> CHECKER =
            (parent, child) -> child.getPermission().startsWith(parent.getPermission());

    // -- Test --

    @ParameterizedTest
    @EnumSource(CapBACScheme.class)
    void registrationAndUsage(CapBACScheme scheme) throws IOException {
        CapBAC<AuthCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);
        long future = Instant.now().getEpochSecond() + 3600;

        // Mutable resolver — adding/removing keys simulates registration/revocation
        Map<PrincipalId, BLSPublicKey> keys = new HashMap<>();
        Resolver resolver = id -> Optional.ofNullable(keys.get(id));

        // --- Step 1: User creates a key pair and proves ownership ---
        Principal user = new Principal(scheme);
        keys.put(user.getId(), scheme.getBls().pkFromBytes(user.getId().toBytes()));

        // Self-issued certificate (issuer == subject) — proves key ownership
        CapBACCertificate selfCert = api.forgeCertificate(user, user.getId(),
                new AuthCapability("self"), future);
        CapBACInvocation proofOfKey = api.invoke(user, selfCert,
                new AuthCapability("self"), future);

        // Service trusts self-issued certs only for registration (trust the user as root)
        TrustChecker trustSelf = id -> id.equals(user.getId());
        assertTrue(proofOfKey.verify(resolver, trustSelf, CODEC, CHECKER),
                "Proof-of-key should verify during registration");

        // --- Step 2: Service registers user and grants API access ---
        Principal service = new Principal(scheme);
        keys.put(service.getId(),
                scheme.getBls().pkFromBytes(service.getId().toBytes()));

        TrustChecker trustService = id -> id.equals(service.getId());

        CapBACCertificate apiGrant = api.forgeCertificate(service, user.getId(),
                new AuthCapability("api:read"), future);
        assertTrue(apiGrant.verify(resolver, trustService, CODEC, CHECKER),
                "Service-issued cert should verify");

        // --- Step 3: User invokes the service-issued cert ---
        CapBACInvocation userInvocation = api.invoke(user, apiGrant,
                new AuthCapability("api:read"), future);
        assertTrue(userInvocation.verify(resolver, trustService, CODEC, CHECKER),
                "User invocation of api:read should pass");

        // --- Step 4: User delegates a narrower scope to a bot ---
        Principal bot = new Principal(scheme);
        keys.put(bot.getId(),
                scheme.getBls().pkFromBytes(bot.getId().toBytes()));

        CapBACCertificate botCert = api.delegateCertificate(user, apiGrant, bot.getId(),
                new AuthCapability("api:read:/metrics"), future);
        CapBACInvocation botInvocation = api.invoke(bot, botCert,
                new AuthCapability("api:read:/metrics"), future);
        assertTrue(botInvocation.verify(resolver, trustService, CODEC, CHECKER),
                "Bot invocation of api:read:/metrics should pass");

        // --- Step 5: Service revokes user by removing their key ---
        keys.remove(user.getId());

        assertFalse(userInvocation.verify(resolver, trustService, CODEC, CHECKER),
                "User invocation should fail after key removal");
        assertFalse(botInvocation.verify(resolver, trustService, CODEC, CHECKER),
                "Bot invocation should also fail — chain depends on user's key");
    }
}
