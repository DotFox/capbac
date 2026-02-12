package dev.dotfox.bls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import supranational.blst.P1;
import supranational.blst.P2;
import supranational.blst.SecretKey;

import dev.dotfox.bls.impl.BlsException;

/**
 * Tests for the public BLS API, parameterized to run for each scheme.
 */
public class BLSTest {
    private static final byte[] MESSAGE = "Hello, World!".getBytes(StandardCharsets.UTF_8);

    // Provides a stream of Arguments, each containing a context and its
    // corresponding scheme.
    static Stream<Arguments> blsContexts() {
        return Stream.of(
                Arguments.of(MinPK.INSTANCE),
                Arguments.of(MinSIG.INSTANCE));
    }

    @Test
    void testBlsException() {
        Throwable cause = new RuntimeException("root cause");
        BlsException exception = new BlsException("test exception", cause);
        assertEquals("test exception", exception.getMessage());
        assertEquals(cause, exception.getCause());
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testKeyGeneration(AbstractBLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getSk());
        assertNotNull(keyPair.getPk());

        // Test if the public key is valid
        assertTrue(keyPair.getPk().getPk().isValid());

        // Assert that the public key has the correct length for the scheme
        byte[] pkBytes = keyPair.getPk().toBytes();
        if (bls.getSchemeName().equals("MINIMAL_PK scheme")) {
            assertEquals(48, pkBytes.length, "Public key should be 48 bytes for MINIMAL_PK scheme.");
        } else {
            assertEquals(96, pkBytes.length, "Public key should be 96 bytes for MINIMAL_SIG scheme.");
        }
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSignAndVerify(AbstractBLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        BLSSignature signature = bls.sign(keyPair.getSk(), MESSAGE);
        assertNotNull(signature);

        // Assert that the signature has the correct length for the scheme
        byte[] sigBytes = signature.getSignature().toBytes();
        if (bls.getSchemeName().equals("MINIMAL_SIG scheme")) {
            assertEquals(48, sigBytes.length, "Signature should be 48 bytes for MINIMAL_SIG scheme.");
        } else {
            assertEquals(96, sigBytes.length, "Signature should be 96 bytes for MINIMAL_PK scheme.");
        }

        // A valid signature should verify correctly
        assertTrue(bls.verify(keyPair.getPk(), MESSAGE, signature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSignAndVerify_failsWithWrongMessage(BLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        BLSSignature signature = bls.sign(keyPair.getSk(), MESSAGE);
        byte[] wrongMessage = "Goodbye, world!".getBytes(StandardCharsets.UTF_8);

        assertFalse(bls.verify(keyPair.getPk(), wrongMessage, signature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSignAndVerify_failsWithWrongPublicKey(BLS bls) {
        BLSKeyPair keyPair1 = bls.keyGen();
        BLSKeyPair keyPair2 = bls.keyGen();
        BLSSignature signature = bls.sign(keyPair1.getSk(), MESSAGE);

        assertFalse(bls.verify(keyPair2.getPk(), MESSAGE, signature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testAggregateSignatures(BLS bls) {
        BLSKeyPair keyPair1 = bls.keyGen();
        BLSKeyPair keyPair2 = bls.keyGen();
        BLSKeyPair keyPair3 = bls.keyGen();

        BLSSignature sig1 = bls.sign(keyPair1.getSk(), MESSAGE);
        BLSSignature sig2 = bls.sign(keyPair2.getSk(), MESSAGE);
        BLSSignature sig3 = bls.sign(keyPair3.getSk(), MESSAGE);

        List<BLSSignature> signatures = Arrays.asList(sig1, sig2, sig3);
        BLSSignature aggregatedSignature = bls.aggregate(signatures);

        assertNotNull(aggregatedSignature);
        assertNotEquals(sig1, aggregatedSignature);
        assertNotEquals(sig2, aggregatedSignature);
        assertNotEquals(sig3, aggregatedSignature);
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testAggregateVerify(BLS bls) {
        List<BLSKeyPair> keyPairs = Stream.generate(bls::keyGen).limit(3).collect(Collectors.toList());
        List<byte[]> messages = IntStream.range(0, 3)
                .mapToObj(i -> ("Message " + i).getBytes(StandardCharsets.UTF_8))
                .collect(Collectors.toList());

        List<BLSSignature> signatures = IntStream.range(0, 3)
                .mapToObj(i -> bls.sign(keyPairs.get(i).getSk(), messages.get(i)))
                .collect(Collectors.toList());

        BLSSignature aggregatedSignature = bls.aggregate(signatures);
        List<BLSPublicKey> publicKeys = keyPairs.stream().map(BLSKeyPair::getPk).collect(Collectors.toList());

        assertTrue(bls.aggregateVerify(publicKeys, messages, aggregatedSignature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testAggregateVerify_failsWithMismatchedMessages(BLS bls) {
        BLSKeyPair keyPair1 = bls.keyGen();
        BLSKeyPair keyPair2 = bls.keyGen();

        byte[] message1 = "Message for key 1".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = "Message for key 2".getBytes(StandardCharsets.UTF_8);

        BLSSignature sig1 = bls.sign(keyPair1.getSk(), message1);
        BLSSignature sig2 = bls.sign(keyPair2.getSk(), message2);

        BLSSignature aggregatedSignature = bls.aggregate(Arrays.asList(sig1, sig2));

        List<BLSPublicKey> publicKeys = Arrays.asList(keyPair1.getPk(), keyPair2.getPk());
        List<byte[]> wrongMessages = Arrays.asList(message2, message1);

        assertFalse(bls.aggregateVerify(publicKeys, wrongMessages, aggregatedSignature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSerializationRoundtrip(BLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        BLSSignature signature = bls.sign(keyPair.getSk(), MESSAGE);

        byte[] pkBytes = keyPair.getPk().toBytes();
        byte[] sigBytes = signature.getSignature().toBytes();

        BLSPublicKey deserializedPk = bls.pkFromBytes(pkBytes);
        BLSSignature deserializedSignature = bls.signatureFromBytes(sigBytes);

        assertEquals(keyPair.getPk(), deserializedPk);
        assertEquals(signature, deserializedSignature);

        assertTrue(bls.verify(deserializedPk, MESSAGE, deserializedSignature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testAggregateVerify_rogueKeySplittingZeroAttack(AbstractBLS bls) {
        BLSKeyPair honestKeyPair = bls.keyGen();
        byte[] honestMessage = "Honest message".getBytes(StandardCharsets.UTF_8);
        BLSSignature honestSignature = bls.sign(honestKeyPair.getSk(), honestMessage);

        BLSKeyPair rogueKeyPair = bls.keyGen();
        SecretKey rogueSk = new SecretKey();
        rogueSk.from_bendian(rogueKeyPair.getSk().toBytes());

        byte[] roguePkBytes;
        byte[] negativeRoguePkBytes;

        if (bls.getSchemeName().equals("MINIMAL_PK scheme")) {
            P1 roguePkPoint = new P1(rogueSk);
            roguePkBytes = roguePkPoint.to_affine().compress();
            negativeRoguePkBytes = roguePkPoint.neg().to_affine().compress();
        } else {
            P2 roguePkPoint = new P2(rogueSk);
            roguePkBytes = roguePkPoint.to_affine().compress();
            negativeRoguePkBytes = roguePkPoint.neg().to_affine().compress();
        }

        List<BLSPublicKey> pksForVerification = Arrays.asList(
                honestKeyPair.getPk(),
                bls.pkFromBytes(roguePkBytes),
                bls.pkFromBytes(negativeRoguePkBytes));

        byte[] rogueMessage = "dummy message".getBytes(StandardCharsets.UTF_8);
        List<byte[]> messagesForVerification = Arrays.asList(honestMessage, rogueMessage, rogueMessage);

        BLSSignature aggregatedSignature = bls.aggregate(Arrays.asList(honestSignature));

        assertFalse(bls.aggregateVerify(pksForVerification, messagesForVerification, aggregatedSignature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testPopProveAndVerify(BLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        BLSSignature proof = bls.popProve(keyPair.getSk());
        assertNotNull(proof);

        assertTrue(bls.popVerify(keyPair.getPk(), proof));

        BLSKeyPair otherKeyPair = bls.keyGen();
        assertFalse(bls.popVerify(otherKeyPair.getPk(), proof));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testAggregateVerifyAugmented_withSameMessage(BLS bls) {
        byte[] commonMessage = "A message signed by multiple parties".getBytes(StandardCharsets.UTF_8);

        BLSKeyPair keyPair1 = bls.keyGen();
        BLSKeyPair keyPair2 = bls.keyGen();

        BLSSignature sig1 = bls.signAugmented(keyPair1.getSk(), commonMessage);
        BLSSignature sig2 = bls.signAugmented(keyPair2.getSk(), commonMessage);

        List<BLSSignature> signatures = Arrays.asList(sig1, sig2);
        BLSSignature aggregatedSignature = bls.aggregate(signatures);

        List<BLSPublicKey> publicKeys = Arrays.asList(keyPair1.getPk(), keyPair2.getPk());
        List<byte[]> messages = Arrays.asList(commonMessage, commonMessage);

        assertTrue(bls.aggregateVerifyAugmented(publicKeys, messages, aggregatedSignature));
        assertFalse(bls.aggregateVerify(publicKeys, messages, aggregatedSignature));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testInvalidDeserialization(BLS bls) {
        // Test with wrong length byte array
        byte[] invalidBytes = "invalid".getBytes();
        assertThrows(IllegalArgumentException.class, () -> bls.pkFromBytes(invalidBytes));
        assertThrows(IllegalArgumentException.class, () -> bls.signatureFromBytes(invalidBytes));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testEmptyAggregate(BLS bls) {
        // Aggregating an empty list of signatures should fail
        assertThrows(BlsException.class, () -> bls.aggregate(Collections.emptyList()));
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSecretKeyDestroy(BLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        byte[] initialKeyBytes = keyPair.getSk().toBytes();

        // Destroy the key
        keyPair.getSk().getSk().destroy();
        byte[] destroyedKeyBytes = keyPair.getSk().toBytes();

        // The destroyed key should be different and all zeros
        assertNotEquals(Arrays.toString(initialKeyBytes), Arrays.toString(destroyedKeyBytes));
        for (byte b : destroyedKeyBytes) {
            assertEquals(0, b);
        }
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testKeyValidation(BLS bls) {
        BLSKeyPair keyPair = bls.keyGen();
        // A legally generated key should be valid.
        assertTrue(keyPair.getPk().getPk().isValid());
    }

    @ParameterizedTest
    @MethodSource("blsContexts")
    void testSecretKeyFromBytes(BLS bls) {
        BLSKeyPair keyPair1 = bls.keyGen();
        byte[] skBytes = keyPair1.getSk().toBytes();

        // Create a new key from the bytes of the first one
        BLSSecretKey skFromBytes = bls.skFromBytes(skBytes);

        // A signature from the deserialized key should be valid with the original
        // public key
        byte[] message = "test".getBytes();
        BLSSignature signature = bls.sign(skFromBytes, message);
        assertTrue(bls.verify(keyPair1.getPk(), message, signature));

        // Test with invalid length
        assertThrows(IllegalArgumentException.class, () -> bls.skFromBytes("invalid".getBytes()));
    }

    @Test
    void testAggregateWithMismatchedSignatureTypes() {
        BLS minPkBls = MinPK.INSTANCE;
        BLS minSigBls = MinSIG.INSTANCE;

        BLSSignature sig1 = minPkBls.sign(minPkBls.keyGen().getSk(), MESSAGE);
        BLSSignature sig2 = minSigBls.sign(minSigBls.keyGen().getSk(), MESSAGE);

        // Attempting to aggregate signatures from different groups should fail
        // This will trigger the catch block in the aggregate method
        assertThrows(ClassCastException.class, () -> {
            minPkBls.aggregate(Arrays.asList(sig1, sig2));
        });
    }
}
