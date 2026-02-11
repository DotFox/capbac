package dev.dotfox.bls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Base64;
import org.junit.jupiter.api.Test;

public class BLSObjectTest {

    private final BLS bls = MinPK.INSTANCE;

    @Test
    void testObjectContracts() {
        BLSKeyPair keyPair1 = bls.keyGen();
        BLSKeyPair keyPair2 = bls.keyGen();

        // Test Public Key
        assertNotEquals(keyPair1.getPk(), keyPair2.getPk());
        assertNotEquals(keyPair1.getPk().hashCode(), keyPair2.getPk().hashCode());
        assertEquals(keyPair1.getPk(), keyPair1.getPk());

        // Test Secret Key
        assertNotEquals(keyPair1.getSk(), keyPair2.getSk());
        assertNotEquals(keyPair1.getSk().hashCode(), keyPair2.getSk().hashCode());
        assertEquals(keyPair1.getSk(), keyPair1.getSk());

        // Test Signature
        byte[] message = "test".getBytes();
        BLSSignature signature1 = bls.sign(keyPair1.getSk(), message);
        BLSSignature signature2 = bls.sign(keyPair2.getSk(), message);

        assertNotEquals(signature1, signature2);
        assertNotEquals(signature1.hashCode(), signature2.hashCode());
        assertEquals(signature1, signature1);
    }

    @Test
    void testToString() {
        BLSKeyPair keyPair = bls.keyGen();
        String pkString = keyPair.getPk().toString();

        assertNotNull(pkString);
        // Check if the string is valid Base64
        try {
            Base64.getDecoder().decode(pkString);
        } catch (IllegalArgumentException e) {
            assertTrue(false, "toString() should return a valid Base64 string.");
        }
    }

    @Test
    void testEqualsAndHashCodeContracts() {
        BLSKeyPair keyPair = bls.keyGen();
        BLSPublicKey pk = keyPair.getPk();
        BLSSignature sig = bls.sign(keyPair.getSk(), "test".getBytes());

        // Test against null and different object types
        assertNotEquals(null, pk);
        assertNotEquals(pk, new Object());

        assertNotEquals(null, sig);
        assertNotEquals(sig, new Object());

        // Test hashCode consistency
        assertEquals(pk.hashCode(), pk.hashCode());
        assertEquals(sig.hashCode(), sig.hashCode());
    }

    @Test
    void testG1ImplementationObjectContracts() {
        BLS bls = MinSIG.INSTANCE; // This scheme uses g1 signatures and g2 keys
        BLSKeyPair keyPair = bls.keyGen();

        dev.dotfox.bls.impl.PublicKey pk1 = keyPair.getPk().getPk();
        dev.dotfox.bls.impl.Signature sig1 = bls.sign(keyPair.getSk(), "test".getBytes()).getSignature();

        // Test against null and different object types
        assertNotEquals(null, pk1);
        assertNotEquals(pk1, new Object());
        assertEquals(pk1, pk1);
        assertNotEquals(pk1.hashCode(), bls.keyGen().getPk().getPk().hashCode());

        assertNotEquals(null, sig1);
        assertNotEquals(sig1, new Object());
        assertEquals(sig1, sig1);
        assertNotEquals(sig1.hashCode(), bls.sign(bls.keyGen().getSk(), "test".getBytes()).getSignature().hashCode());
    }

    @Test
    void testG2ImplementationObjectContracts() {
        BLS bls = MinPK.INSTANCE; // This scheme uses g2 signatures and g1 keys
        BLSKeyPair keyPair = bls.keyGen();

        dev.dotfox.bls.impl.PublicKey pk1 = keyPair.getPk().getPk();
        dev.dotfox.bls.impl.Signature sig1 = bls.sign(keyPair.getSk(), "test".getBytes()).getSignature();

        // Test against null and different object types
        assertNotEquals(null, pk1);
        assertNotEquals(pk1, new Object());
        assertEquals(pk1, pk1);
        assertNotEquals(pk1.hashCode(), bls.keyGen().getPk().getPk().hashCode());

        assertNotEquals(null, sig1);
        assertNotEquals(sig1, new Object());
        assertEquals(sig1, sig1);
        assertNotEquals(sig1.hashCode(), bls.sign(bls.keyGen().getSk(), "test".getBytes()).getSignature().hashCode());
    }

    @Test
    void testBlstLoader() {
        // This test ensures the loader successfully finds and initializes the
        // libraries.
        assertTrue(dev.dotfox.bls.impl.blst.BlstLoader.INSTANCE_G1.isPresent());
        assertTrue(dev.dotfox.bls.impl.blst.BlstLoader.INSTANCE_G2.isPresent());
    }
}
