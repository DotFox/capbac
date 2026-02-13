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
 * Demonstrates a device manufacturing supply chain using CapBAC.
 *
 * A manufacturer delegates authority to factories, factories to production batches,
 * and batches to individual devices — forming a 3-hop delegation chain.
 * Removing a batch or factory key revokes all downstream devices instantly.
 */
public class DeviceManufacturingExampleTest {

    // -- Domain types --

    static final class DeviceCapability implements Capability {
        private final String scope;

        DeviceCapability(String scope) {
            this.scope = Objects.requireNonNull(scope);
        }

        String getScope() { return scope; }

        @Override
        public byte[] toBytes() {
            return scope.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof DeviceCapability that && Objects.equals(scope, that.scope));
        }

        @Override
        public int hashCode() { return Objects.hash(scope); }
    }

    static final CapabilityCodec<DeviceCapability> CODEC =
            bytes -> new DeviceCapability(new String(bytes, StandardCharsets.UTF_8));

    // Attenuation: child scope must be a prefix-narrowing of parent scope
    static final AttenuationChecker<DeviceCapability> CHECKER =
            (parent, child) -> child.getScope().startsWith(parent.getScope());

    // -- Test --

    @ParameterizedTest
    @EnumSource(CapBACScheme.class)
    void deviceChainAndBatchRevocation(CapBACScheme scheme) throws IOException {
        CapBAC<DeviceCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);
        long future = Instant.now().getEpochSecond() + 3600;
        OptionalLong ce = scheme.hasExpiringCerts() ? OptionalLong.of(future) : OptionalLong.empty();

        Map<PrincipalId, BLSPublicKey> keys = new HashMap<>();
        Resolver resolver = id -> Optional.ofNullable(keys.get(id));

        // --- Create principals ---
        Principal manufacturer = new Principal(scheme);
        Principal factoryA = new Principal(scheme);
        Principal batchA = new Principal(scheme);
        Principal deviceA = new Principal(scheme);

        Principal factoryB = new Principal(scheme);
        Principal deviceB = new Principal(scheme);

        for (Principal p : new Principal[]{manufacturer, factoryA, batchA, deviceA, factoryB, deviceB}) {
            keys.put(p.getId(), scheme.getBls().pkFromBytes(p.getId().toBytes()));
        }

        TrustChecker trustManufacturer = id -> id.equals(manufacturer.getId());

        // --- Step 1: Manufacturer → Factory A ---
        CapBACCertificate factoryACert = api.forgeCertificate(manufacturer, factoryA.getId(),
                new DeviceCapability("factory-a"), ce);

        // --- Step 2: Factory A → Batch ---
        CapBACCertificate batchACert = api.delegateCertificate(factoryA, factoryACert, batchA.getId(),
                new DeviceCapability("factory-a:batch-2024-03"), ce);

        // --- Step 3: Batch → Device ---
        CapBACCertificate deviceACert = api.delegateCertificate(batchA, batchACert, deviceA.getId(),
                new DeviceCapability("factory-a:batch-2024-03:serial-00042"), ce);

        // --- Step 4: Device invokes — full 3-hop chain verifies ---
        CapBACInvocation deviceAInvocation = api.invoke(deviceA, deviceACert,
                new DeviceCapability("factory-a:batch-2024-03:serial-00042"), future);
        assertTrue(deviceAInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Device A invocation should verify through 3-hop chain");

        // --- Set up Factory B with its own device ---
        CapBACCertificate factoryBCert = api.forgeCertificate(manufacturer, factoryB.getId(),
                new DeviceCapability("factory-b"), ce);
        CapBACCertificate deviceBCert = api.delegateCertificate(factoryB, factoryBCert, deviceB.getId(),
                new DeviceCapability("factory-b:device-001"), ce);
        CapBACInvocation deviceBInvocation = api.invoke(deviceB, deviceBCert,
                new DeviceCapability("factory-b:device-001"), future);
        assertTrue(deviceBInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Factory B device should also verify");

        // --- Step 5: Revoke the batch key — device A fails ---
        keys.remove(batchA.getId());
        assertFalse(deviceAInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Device A should fail after batch key revocation");

        // --- Step 6: Factory B device is unaffected ---
        assertTrue(deviceBInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Factory B device should still verify — different chain");

        // --- Step 7: Revoke Factory A key — all Factory A devices fail ---
        keys.remove(factoryA.getId());
        assertFalse(deviceAInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Device A still fails (batch already revoked)");

        // Factory B still works
        assertTrue(deviceBInvocation.verify(resolver, trustManufacturer, CODEC, CHECKER),
                "Factory B device unaffected by Factory A revocation");
    }
}
