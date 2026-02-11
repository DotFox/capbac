package dev.dotfox.capbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSKeyPair;
import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.bls.BLSSignature;

public class CapBACTest {

    private BLS bls;
    private BLSKeyPair rootKeyPair;
    private BLSKeyPair intermediateKeyPair;
    private BLSKeyPair userKeyPair;

    private byte[] rootId;
    private byte[] intermediateId;
    private byte[] userId;

    private Map<ByteArrayWrapper, BLSPublicKey> resolverMap;
    private Resolver resolver;
    private TrustChecker trustChecker;

    // Wrapper class to use byte[] as a key in a Map
    private static class ByteArrayWrapper {
        private final byte[] data;

        public ByteArrayWrapper(byte[] data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            ByteArrayWrapper that = (ByteArrayWrapper) o;
            return Arrays.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }

    void setupForScheme(CapBACScheme scheme) {
        this.bls = scheme.getBls();
        this.rootKeyPair = this.bls.keyGen();
        this.intermediateKeyPair = this.bls.keyGen();
        this.userKeyPair = this.bls.keyGen();

        this.rootId = this.rootKeyPair.getPk().toBytes();
        this.intermediateId = this.intermediateKeyPair.getPk().toBytes();
        this.userId = this.userKeyPair.getPk().toBytes();

        this.resolverMap = new HashMap<>();
        this.resolverMap.put(new ByteArrayWrapper(rootId), rootKeyPair.getPk());
        this.resolverMap.put(new ByteArrayWrapper(intermediateId), intermediateKeyPair.getPk());
        this.resolverMap.put(new ByteArrayWrapper(userId), userKeyPair.getPk());

        this.resolver = id -> resolverMap.get(new ByteArrayWrapper(id));
        this.trustChecker = id -> Arrays.equals(id, rootId);
    }

    private CapBACInvocation createValidInvocationToken(CapBACScheme scheme, long expiration) {
        List<Certificate> chain = createCertificateChain(expiration);
        Invocation invocation = new Invocation(userId, expiration, chain.get(1).getRawCapability());

        List<BLSSignature> signatures = chain.stream().map(cert -> {
            if (Arrays.equals(cert.getIssuer(), rootId))
                return bls.sign(rootKeyPair.getSk(), cert.toBytes());
            return bls.sign(intermediateKeyPair.getSk(), cert.toBytes());
        }).collect(Collectors.toList());
        signatures.add(bls.sign(userKeyPair.getSk(), invocation.toBytes()));

        BLSSignature aggregateSignature = bls.aggregate(signatures);
        return new CapBACInvocation(scheme, chain, invocation, aggregateSignature);
    }

    private CapBACCertificate createValidCertificateToken(CapBACScheme scheme, long expiration) {
        List<Certificate> chain = createCertificateChain(expiration);

        List<BLSSignature> signatures = chain.stream().map(cert -> {
            if (Arrays.equals(cert.getIssuer(), rootId))
                return bls.sign(rootKeyPair.getSk(), cert.toBytes());
            return bls.sign(intermediateKeyPair.getSk(), cert.toBytes());
        }).collect(Collectors.toList());

        BLSSignature aggregateSignature = bls.aggregate(signatures);
        return new CapBACCertificate(scheme, chain, aggregateSignature);
    }

    private List<Certificate> createCertificateChain(long expiration) {
        byte[] cap1Bytes = new StringCapability("read").toBytes();
        Certificate cert1 = new Certificate(rootId, intermediateId, expiration, cap1Bytes);
        byte[] cap2Bytes = new StringCapability("read:/data/file.txt").toBytes();
        Certificate cert2 = new Certificate(intermediateId, userId, expiration, cap2Bytes);
        return Arrays.asList(cert1, cert2);
    }

    @Nested
    class HighLevelAPITests {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testForgeDelegateAndInvoke(CapBACScheme scheme) {
            setupForScheme(scheme);
            CapBAC api = new CapBAC(scheme);

            Principal rootPrincipal = new Principal(bls, rootKeyPair);
            Principal intermediatePrincipal = new Principal(bls, intermediateKeyPair);
            Principal userPrincipal = new Principal(bls, userKeyPair);

            long expiration = Instant.now().getEpochSecond() + 3600;
            StringCapability readCap = new StringCapability("read");
            StringCapability fileCap = new StringCapability("read:/data/file.txt");

            // 1. Forge
            CapBACCertificate rootCert = api.forgeCertificate(rootPrincipal, intermediatePrincipal.getId(), readCap,
                    expiration);
            assertTrue(rootCert.verify(resolver, trustChecker));

            // 2. Delegate
            CapBACCertificate delegatedCert = api.delegateCertificate(intermediatePrincipal, rootCert,
                    userPrincipal.getId(),
                    fileCap, expiration);
            assertTrue(delegatedCert.verify(resolver, trustChecker));

            // 3. Invoke
            CapBACInvocation invocationToken = api.invoke(userPrincipal, delegatedCert, fileCap, expiration);
            assertTrue(invocationToken.verify(resolver, trustChecker));
        }
    }

    @Nested
    class InvocationTokenTests {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testTokenCreationAndVerification(CapBACScheme scheme) {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation token = createValidInvocationToken(scheme, validExpiration);
            assertTrue(token.verify(resolver, trustChecker), "Invocation token should be valid");
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testSerializationDeserialization(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation originalToken = createValidInvocationToken(scheme, validExpiration);

            byte[] serializedToken = originalToken.toBytes();
            CapBACToken deserializedToken = CapBACToken.fromBytes(serializedToken);

            assertTrue(deserializedToken instanceof CapBACInvocation);
            assertTrue(deserializedToken.verify(resolver, trustChecker),
                    "Deserialized invocation token should be valid");
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testCapabilityDecoding(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation originalToken = createValidInvocationToken(scheme, validExpiration);

            byte[] serializedToken = originalToken.toBytes();
            CapBACInvocation deserializedToken = (CapBACInvocation) CapBACToken.fromBytes(serializedToken);

            StringCapability expectedCap = new StringCapability("read:/data/file.txt");
            StringCapability actualCap = deserializedToken.getInvocation().getCapability(new StringCapabilityCodec());

            assertEquals(expectedCap, actualCap);
        }
    }

    @Nested
    class CertificateTokenTests {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testTokenCreationAndVerification(CapBACScheme scheme) {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACCertificate token = createValidCertificateToken(scheme, validExpiration);
            assertTrue(token.verify(resolver, trustChecker), "Certificate token should be valid");
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testSerializationDeserialization(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACCertificate originalToken = createValidCertificateToken(scheme, validExpiration);

            byte[] serializedToken = originalToken.toBytes();
            CapBACToken deserializedToken = CapBACToken.fromBytes(serializedToken);

            assertTrue(deserializedToken instanceof CapBACCertificate);
            assertTrue(deserializedToken.verify(resolver, trustChecker),
                    "Deserialized certificate token should be valid");
        }
    }

    @Nested
    class InvocationTokenFailures {
        @BeforeEach
        void nestedSetup() {
            setupForScheme(CapBACScheme.MIN_PK);
        }

        @Test
        void testFail_ExpiredToken() {
            long pastExpiration = Instant.now().getEpochSecond() - 3600;
            CapBACInvocation token = createValidInvocationToken(CapBACScheme.MIN_PK, pastExpiration);
            assertFalse(token.verify(resolver, trustChecker));
        }

        @Test
        void testFail_UntrustedRoot() {
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation token = createValidInvocationToken(CapBACScheme.MIN_PK, validExpiration);
            assertFalse(token.verify(resolver, id -> false));
        }

        @Test
        void testFail_BrokenDelegationChain() {
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            BLSKeyPair anotherKeyPair = bls.keyGen();
            byte[] anotherId = anotherKeyPair.getPk().toBytes();
            resolverMap.put(new ByteArrayWrapper(anotherId), anotherKeyPair.getPk());

            // Create a broken chain
            byte[] cap1Bytes = new StringCapability("read").toBytes();
            Certificate cert1 = new Certificate(rootId, intermediateId, validExpiration, cap1Bytes);
            byte[] cap2Bytes = new StringCapability("read:/data/file.txt").toBytes();
            Certificate cert2 = new Certificate(intermediateId, anotherId, validExpiration, cap2Bytes);
            List<Certificate> brokenChain = Arrays.asList(cert1, cert2);

            Invocation invocation = new Invocation(userId, validExpiration, cert2.getRawCapability());

            BLSSignature sig1 = bls.sign(rootKeyPair.getSk(), cert1.toBytes());
            BLSSignature sig2 = bls.sign(intermediateKeyPair.getSk(), cert2.toBytes());
            BLSSignature sig3 = bls.sign(anotherKeyPair.getSk(), invocation.toBytes());
            BLSSignature aggregateSignature = bls.aggregate(Arrays.asList(sig1, sig2, sig3));

            CapBACInvocation token = new CapBACInvocation(CapBACScheme.MIN_PK, brokenChain, invocation,
                    aggregateSignature);
            assertFalse(token.verify(resolver, trustChecker));
        }
    }

    @Nested
    class DeserializationFailures {
        @Test
        void testFail_InvalidTokenType() {
            byte[] badData = new byte[] { 0x03, 0x01, 0x02, 0x03 }; // Invalid type 0x03
            assertThrows(IOException.class, () -> CapBACToken.fromBytes(badData));
        }

        @Test
        void testFail_ExtraBytesInToken() throws IOException {
            setupForScheme(CapBACScheme.MIN_PK);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation token = createValidInvocationToken(CapBACScheme.MIN_PK, validExpiration);
            byte[] originalBytes = token.toBytes();

            byte[] tamperedBytes = new byte[originalBytes.length + 5];
            System.arraycopy(originalBytes, 0, tamperedBytes, 0, originalBytes.length);
            Arrays.fill(tamperedBytes, originalBytes.length, tamperedBytes.length, (byte) 0x01);

            assertThrows(IOException.class, () -> CapBACToken.fromBytes(tamperedBytes));
        }
    }
}
