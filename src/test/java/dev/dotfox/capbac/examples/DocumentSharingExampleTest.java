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
 * Demonstrates document sharing with hierarchical permissions using CapBAC.
 *
 * An owner holds EDIT access, delegates COMMENT to a colleague, who further
 * delegates VIEW to a reviewer. Permissions can only be narrowed (EDIT → COMMENT → VIEW).
 * Revoking the colleague's key cascades to the reviewer.
 */
public class DocumentSharingExampleTest {

    // -- Domain types --

    enum Permission {
        EDIT,    // ordinal 0 — broadest
        COMMENT, // ordinal 1
        VIEW;    // ordinal 2 — narrowest
    }

    static final class DocCapability implements Capability {
        private final String docId;
        private final Permission permission;

        DocCapability(String docId, Permission permission) {
            this.docId = Objects.requireNonNull(docId);
            this.permission = Objects.requireNonNull(permission);
        }

        String getDocId() { return docId; }
        Permission getPermission() { return permission; }

        @Override
        public byte[] toBytes() {
            String encoded = docId + "|" + permission.name();
            return encoded.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean equals(Object o) {
            return this == o || (o instanceof DocCapability that
                    && Objects.equals(docId, that.docId)
                    && permission == that.permission);
        }

        @Override
        public int hashCode() { return Objects.hash(docId, permission); }
    }

    static final CapabilityCodec<DocCapability> CODEC = bytes -> {
        String s = new String(bytes, StandardCharsets.UTF_8);
        int sep = s.indexOf('|');
        if (sep < 0) throw new IOException("Invalid DocCapability encoding: " + s);
        String docId = s.substring(0, sep);
        Permission perm = Permission.valueOf(s.substring(sep + 1));
        return new DocCapability(docId, perm);
    };

    // Attenuation: same doc required, child permission ordinal must be >= parent's (narrower)
    static final AttenuationChecker<DocCapability> CHECKER = (parent, child) ->
            parent.getDocId().equals(child.getDocId())
                    && child.getPermission().ordinal() >= parent.getPermission().ordinal();

    // -- Test --

    @ParameterizedTest
    @EnumSource(CapBACScheme.class)
    void sharingAndRevocation(CapBACScheme scheme) throws IOException {
        CapBAC<DocCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);
        long future = Instant.now().getEpochSecond() + 3600;

        Map<PrincipalId, BLSPublicKey> keys = new HashMap<>();
        Resolver resolver = id -> Optional.ofNullable(keys.get(id));

        // --- Create principals ---
        Principal owner = new Principal(scheme);
        Principal colleague = new Principal(scheme);
        Principal reviewer = new Principal(scheme);

        for (Principal p : new Principal[]{owner, colleague, reviewer}) {
            keys.put(p.getId(), scheme.getBls().pkFromBytes(p.getId().toBytes()));
        }

        TrustChecker trustOwner = id -> id.equals(owner.getId());

        // --- Step 1: Owner holds doc:abc123:EDIT ---
        CapBACCertificate ownerCert = api.forgeCertificate(owner, owner.getId(),
                new DocCapability("abc123", Permission.EDIT), future);
        assertTrue(ownerCert.verify(resolver, trustOwner, CODEC, CHECKER));

        // --- Step 2: Owner delegates COMMENT to colleague ---
        CapBACCertificate colleagueCert = api.delegateCertificate(owner, ownerCert, colleague.getId(),
                new DocCapability("abc123", Permission.COMMENT), future);
        assertTrue(colleagueCert.verify(resolver, trustOwner, CODEC, CHECKER));

        // --- Step 3: Colleague delegates VIEW to reviewer ---
        CapBACCertificate reviewerCert = api.delegateCertificate(colleague, colleagueCert, reviewer.getId(),
                new DocCapability("abc123", Permission.VIEW), future);

        // --- Step 4: Reviewer invokes VIEW — passes ---
        CapBACInvocation reviewerInvocation = api.invoke(reviewer, reviewerCert,
                new DocCapability("abc123", Permission.VIEW), future);
        assertTrue(reviewerInvocation.verify(resolver, trustOwner, CODEC, CHECKER),
                "Reviewer should be able to VIEW the document");

        // --- Step 5: Reviewer tries COMMENT — attenuation fails ---
        assertThrows(IllegalArgumentException.class, () ->
                        api.invoke(reviewer, reviewerCert,
                                new DocCapability("abc123", Permission.COMMENT), future),
                "Reviewer should not be able to escalate to COMMENT");

        // --- Step 6: Remove colleague key — reviewer also loses access ---
        keys.remove(colleague.getId());
        assertFalse(reviewerInvocation.verify(resolver, trustOwner, CODEC, CHECKER),
                "Reviewer should lose access when colleague's key is revoked");
    }
}
