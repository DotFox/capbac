package dev.dotfox.capbac.examples;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

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
 * Demonstrates smart home access delegation with expiry using CapBAC.
 *
 * A homeowner delegates device access to family members, who can further
 * delegate to guests with time-limited tokens. Expired tokens are rejected,
 * attenuation prevents scope escalation, and removing a family member's key
 * breaks the guest's chain.
 */
public class SmartHomeExampleTest {

    // -- Domain types --

    static final class HomeCapability implements Capability {
        private final String scope;

        HomeCapability(String scope) {
            this.scope = Objects.requireNonNull(scope);
        }

        String getScope() { return scope; }

        @Override
        public byte[] toBytes() {
            return scope.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof HomeCapability that && Objects.equals(scope, that.scope));
        }

        @Override
        public int hashCode() { return Objects.hash(scope); }
    }

    static final CapabilityCodec<HomeCapability> CODEC =
            bytes -> new HomeCapability(new String(bytes, StandardCharsets.UTF_8));

    // Attenuation: child scope must start with parent scope
    static final AttenuationChecker<HomeCapability> CHECKER =
            (parent, child) -> child.getScope().startsWith(parent.getScope());

    // -- Test --

    @ParameterizedTest
    @EnumSource(CapBACScheme.class)
    void delegationAndExpiry(CapBACScheme scheme) throws IOException {
        CapBAC<HomeCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);
        long future = Instant.now().getEpochSecond() + 3600;
        long past = Instant.now().getEpochSecond() - 3600;
        OptionalLong ceFuture = scheme.hasExpiringCerts() ? OptionalLong.of(future) : OptionalLong.empty();
        OptionalLong cePast = scheme.hasExpiringCerts() ? OptionalLong.of(past) : OptionalLong.empty();

        Map<PrincipalId, BLSPublicKey> keys = new HashMap<>();
        Resolver resolver = id -> Optional.ofNullable(keys.get(id));

        // --- Create principals ---
        Principal homeowner = new Principal(scheme);
        Principal familyMember = new Principal(scheme);
        Principal guest = new Principal(scheme);

        for (Principal p : new Principal[]{homeowner, familyMember, guest}) {
            keys.put(p.getId(), scheme.getBls().pkFromBytes(p.getId().toBytes()));
        }

        TrustChecker trustOwner = id -> id.equals(homeowner.getId());

        // --- Step 1: Homeowner forges root cert to self ---
        CapBACCertificate ownerCert = api.forgeCertificate(homeowner, homeowner.getId(),
                new HomeCapability("home"), ceFuture);
        assertTrue(ownerCert.verify(resolver, trustOwner, CODEC, CHECKER));

        // --- Step 2: Homeowner delegates "home:lights" to family member ---
        CapBACCertificate familyCert = api.delegateCertificate(homeowner, ownerCert, familyMember.getId(),
                new HomeCapability("home:lights"), ceFuture);
        assertTrue(familyCert.verify(resolver, trustOwner, CODEC, CHECKER));

        // --- Step 3: Family member delegates to guest with PAST expiry ---
        // For non-expiring schemes, certs don't carry expiry so this cert is valid;
        // the expiry only matters on the invocation.
        CapBACCertificate guestCert = api.delegateCertificate(familyMember, familyCert, guest.getId(),
                new HomeCapability("home:lights:living-room"), cePast);

        // --- Step 4: Guest invokes with past expiry — fails due to invocation expiry ---
        CapBACInvocation expiredInvocation = api.invoke(guest, guestCert,
                new HomeCapability("home:lights:living-room"), past);
        assertFalse(expiredInvocation.verify(resolver, trustOwner, CODEC, CHECKER),
                "Expired guest invocation should fail");

        // --- Step 5: Family member re-delegates with future expiry — passes ---
        CapBACCertificate validGuestCert = api.delegateCertificate(familyMember, familyCert, guest.getId(),
                new HomeCapability("home:lights:living-room"), ceFuture);
        CapBACInvocation validInvocation = api.invoke(guest, validGuestCert,
                new HomeCapability("home:lights:living-room"), future);
        assertTrue(validInvocation.verify(resolver, trustOwner, CODEC, CHECKER),
                "Valid guest invocation should pass");

        // --- Step 6: Guest tries to invoke "home:lights:kitchen" — attenuation fails ---
        // Guest's cert is scoped to "home:lights:living-room", so "home:lights:kitchen" is not a valid attenuation
        assertThrows(IllegalArgumentException.class, () ->
                        api.invoke(guest, validGuestCert, new HomeCapability("home:lights:kitchen"), future),
                "Guest should not be able to invoke outside their scope");

        // --- Step 7: Remove family member key — guest's chain breaks ---
        keys.remove(familyMember.getId());
        assertFalse(validInvocation.verify(resolver, trustOwner, CODEC, CHECKER),
                "Guest invocation should fail after family member key removal");
    }
}
