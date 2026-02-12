package dev.dotfox.capbac.examples;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

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
 * Demonstrates microservice-to-microservice auth with least-privilege using CapBAC.
 *
 * A gateway grants resource+action capabilities to downstream services.
 * Services can delegate narrower scopes (fewer actions, more specific resource paths).
 * The aggregate signature enables O(1) verification regardless of chain length.
 */
public class MicroserviceAuthExampleTest {

    // -- Domain types --

    static final class RequestCapability implements Capability {
        private final String resource;
        private final Set<String> actions;

        RequestCapability(String resource, Set<String> actions) {
            this.resource = Objects.requireNonNull(resource);
            this.actions = Collections.unmodifiableSet(new TreeSet<>(actions));
        }

        String getResource() { return resource; }
        Set<String> getActions() { return actions; }

        @Override
        public byte[] toBytes() {
            // Serialization format: "resource|action1,action2" (sorted actions for determinism)
            String encoded = resource + "|" + String.join(",", actions);
            return encoded.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof RequestCapability that
                    && Objects.equals(resource, that.resource)
                    && Objects.equals(actions, that.actions));
        }

        @Override
        public int hashCode() { return Objects.hash(resource, actions); }
    }

    static final CapabilityCodec<RequestCapability> CODEC = bytes -> {
        String s = new String(bytes, StandardCharsets.UTF_8);
        int sep = s.indexOf('|');
        if (sep < 0) throw new IOException("Invalid RequestCapability encoding: " + s);
        String resource = s.substring(0, sep);
        Set<String> actions = new TreeSet<>(Arrays.asList(s.substring(sep + 1).split(",")));
        return new RequestCapability(resource, actions);
    };

    // Attenuation: child resource must be same-or-narrower prefix AND actions must be a subset
    static final AttenuationChecker<RequestCapability> CHECKER = (parent, child) ->
            child.getResource().startsWith(parent.getResource())
                    && parent.getActions().containsAll(child.getActions());

    // -- Test --

    @ParameterizedTest
    @EnumSource(CapBACScheme.class)
    void requestFlowAndLeastPrivilege(CapBACScheme scheme) throws IOException {
        CapBAC<RequestCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);
        long future = Instant.now().getEpochSecond() + 3600;

        Map<PrincipalId, BLSPublicKey> keys = new HashMap<>();
        Resolver resolver = id -> Optional.ofNullable(keys.get(id));

        // --- Create principals ---
        Principal gateway = new Principal(scheme);
        Principal orderService = new Principal(scheme);
        Principal inventoryService = new Principal(scheme);

        for (Principal p : new Principal[]{gateway, orderService, inventoryService}) {
            keys.put(p.getId(), scheme.getBls().pkFromBytes(p.getId().toBytes()));
        }

        TrustChecker trustGateway = id -> id.equals(gateway.getId());

        // --- Step 1: Gateway forges "orders:read,write" to Order Service ---
        RequestCapability ordersCap = new RequestCapability("orders",
                new TreeSet<>(Arrays.asList("read", "write")));
        CapBACCertificate orderServiceCert = api.forgeCertificate(gateway, orderService.getId(),
                ordersCap, future);
        assertTrue(orderServiceCert.verify(resolver, trustGateway, CODEC, CHECKER));

        // --- Step 2: Order Service delegates "orders/123:read" to Inventory Service ---
        RequestCapability narrowCap = new RequestCapability("orders/123",
                Collections.singleton("read"));
        CapBACCertificate inventoryCert = api.delegateCertificate(orderService, orderServiceCert,
                inventoryService.getId(), narrowCap, future);

        // --- Step 3: Inventory Service invokes — single aggregate verify ---
        CapBACInvocation inventoryInvocation = api.invoke(inventoryService, inventoryCert,
                narrowCap, future);
        assertTrue(inventoryInvocation.verify(resolver, trustGateway, CODEC, CHECKER),
                "Inventory service invocation should pass with narrowed capability");

        // --- Step 4: Inventory Service tries broader scope — attenuation fails ---
        assertThrows(IllegalArgumentException.class, () ->
                        api.invoke(inventoryService, inventoryCert, ordersCap, future),
                "Inventory service should not be able to escalate to orders:read,write");

        // --- Step 5: Remove Order Service key — in-flight requests fail ---
        keys.remove(orderService.getId());
        assertFalse(inventoryInvocation.verify(resolver, trustGateway, CODEC, CHECKER),
                "Inventory invocation should fail after Order Service key removal");
    }
}
