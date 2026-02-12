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

    private static final StringCapabilityCodec CODEC = new StringCapabilityCodec();
    private static final AttenuationChecker<StringCapability> CHECKER =
            (parent, child) -> child.getValue().startsWith(parent.getValue());

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

        this.resolver = id -> java.util.Optional.ofNullable(resolverMap.get(new ByteArrayWrapper(id)));
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
        void testForgeDelegateAndInvoke(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            CapBAC<StringCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);

            Principal rootPrincipal = new Principal(bls, rootKeyPair);
            Principal intermediatePrincipal = new Principal(bls, intermediateKeyPair);
            Principal userPrincipal = new Principal(bls, userKeyPair);

            long expiration = Instant.now().getEpochSecond() + 3600;
            StringCapability readCap = new StringCapability("read");
            StringCapability fileCap = new StringCapability("read:/data/file.txt");

            // 1. Forge
            CapBACCertificate rootCert = api.forgeCertificate(rootPrincipal, intermediatePrincipal.getId(), readCap,
                    expiration);
            assertTrue(rootCert.verify(resolver, trustChecker, CODEC, CHECKER));

            // 2. Delegate
            CapBACCertificate delegatedCert = api.delegateCertificate(intermediatePrincipal, rootCert,
                    userPrincipal.getId(),
                    fileCap, expiration);
            assertTrue(delegatedCert.verify(resolver, trustChecker, CODEC, CHECKER));

            // 3. Invoke
            CapBACInvocation invocationToken = api.invoke(userPrincipal, delegatedCert, fileCap, expiration);
            assertTrue(invocationToken.verify(resolver, trustChecker, CODEC, CHECKER));
        }
    }

    @Nested
    class InvocationTokenTests {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testTokenCreationAndVerification(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation token = createValidInvocationToken(scheme, validExpiration);
            assertTrue(token.verify(resolver, trustChecker, CODEC, CHECKER), "Invocation token should be valid");
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
            assertTrue(deserializedToken.verify(resolver, trustChecker, CODEC, CHECKER),
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
        void testTokenCreationAndVerification(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACCertificate token = createValidCertificateToken(scheme, validExpiration);
            assertTrue(token.verify(resolver, trustChecker, CODEC, CHECKER), "Certificate token should be valid");
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
            assertTrue(deserializedToken.verify(resolver, trustChecker, CODEC, CHECKER),
                    "Deserialized certificate token should be valid");
        }
    }

    @Nested
    class InvocationTokenFailures {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_ExpiredToken(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long pastExpiration = Instant.now().getEpochSecond() - 3600;
            CapBACInvocation token = createValidInvocationToken(scheme, pastExpiration);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_UntrustedRoot(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACInvocation token = createValidInvocationToken(scheme, validExpiration);
            assertFalse(token.verify(resolver, id -> false, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_BrokenDelegationChain(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
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

            CapBACInvocation token = new CapBACInvocation(scheme, brokenChain, invocation,
                    aggregateSignature);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_AttenuationViolation(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;

            // Root grants "read:/data/file.txt" (narrow)
            byte[] cap1Bytes = new StringCapability("read:/data/file.txt").toBytes();
            Certificate cert1 = new Certificate(rootId, intermediateId, validExpiration, cap1Bytes);
            // Intermediate delegates "read" (broader than parent) — escalation
            byte[] cap2Bytes = new StringCapability("read:/data/file.txt").toBytes();
            Certificate cert2 = new Certificate(intermediateId, userId, validExpiration, cap2Bytes);
            List<Certificate> chain = Arrays.asList(cert1, cert2);

            // Invocation uses "read" — broader than last cert
            Invocation invocation = new Invocation(userId, validExpiration, new StringCapability("read").toBytes());

            BLSSignature sig1 = bls.sign(rootKeyPair.getSk(), cert1.toBytes());
            BLSSignature sig2 = bls.sign(intermediateKeyPair.getSk(), cert2.toBytes());
            BLSSignature sig3 = bls.sign(userKeyPair.getSk(), invocation.toBytes());
            BLSSignature aggregateSignature = bls.aggregate(Arrays.asList(sig1, sig2, sig3));

            CapBACInvocation token = new CapBACInvocation(scheme, chain, invocation, aggregateSignature);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }
    }

    @Nested
    class CertificateTokenFailures {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_ExpiredToken(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long pastExpiration = Instant.now().getEpochSecond() - 3600;
            CapBACCertificate token = createValidCertificateToken(scheme, pastExpiration);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_UntrustedRoot(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            CapBACCertificate token = createValidCertificateToken(scheme, validExpiration);
            assertFalse(token.verify(resolver, id -> false, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_BrokenDelegationChain(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;
            BLSKeyPair anotherKeyPair = bls.keyGen();
            byte[] anotherId = anotherKeyPair.getPk().toBytes();
            resolverMap.put(new ByteArrayWrapper(anotherId), anotherKeyPair.getPk());

            // Create a broken chain: cert2 issuer doesn't match cert1 subject
            byte[] cap1Bytes = new StringCapability("read").toBytes();
            Certificate cert1 = new Certificate(rootId, intermediateId, validExpiration, cap1Bytes);
            byte[] cap2Bytes = new StringCapability("read:/data/file.txt").toBytes();
            Certificate cert2 = new Certificate(anotherId, userId, validExpiration, cap2Bytes);
            List<Certificate> brokenChain = Arrays.asList(cert1, cert2);

            BLSSignature sig1 = bls.sign(rootKeyPair.getSk(), cert1.toBytes());
            BLSSignature sig2 = bls.sign(anotherKeyPair.getSk(), cert2.toBytes());
            BLSSignature aggregateSignature = bls.aggregate(Arrays.asList(sig1, sig2));

            CapBACCertificate token = new CapBACCertificate(scheme, brokenChain, aggregateSignature);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_AttenuationViolation(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            long validExpiration = Instant.now().getEpochSecond() + 3600;

            // Root grants "read:/data/file.txt" (narrow)
            byte[] cap1Bytes = new StringCapability("read:/data/file.txt").toBytes();
            Certificate cert1 = new Certificate(rootId, intermediateId, validExpiration, cap1Bytes);
            // Intermediate delegates "read" (broader than parent) — escalation
            byte[] cap2Bytes = new StringCapability("write").toBytes();
            Certificate cert2 = new Certificate(intermediateId, userId, validExpiration, cap2Bytes);
            List<Certificate> chain = Arrays.asList(cert1, cert2);

            BLSSignature sig1 = bls.sign(rootKeyPair.getSk(), cert1.toBytes());
            BLSSignature sig2 = bls.sign(intermediateKeyPair.getSk(), cert2.toBytes());
            BLSSignature aggregateSignature = bls.aggregate(Arrays.asList(sig1, sig2));

            CapBACCertificate token = new CapBACCertificate(scheme, chain, aggregateSignature);
            assertFalse(token.verify(resolver, trustChecker, CODEC, CHECKER));
        }
    }

    @Nested
    class AttenuationEnforcementTests {
        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_DelegateWithBroaderCapability(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            CapBAC<StringCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);

            Principal rootPrincipal = new Principal(bls, rootKeyPair);
            Principal intermediatePrincipal = new Principal(bls, intermediateKeyPair);

            long expiration = Instant.now().getEpochSecond() + 3600;
            StringCapability narrowCap = new StringCapability("read:/data/file.txt");
            StringCapability broadCap = new StringCapability("write");

            CapBACCertificate rootCert = api.forgeCertificate(rootPrincipal, intermediatePrincipal.getId(), narrowCap,
                    expiration);

            assertThrows(IllegalArgumentException.class, () ->
                    api.delegateCertificate(intermediatePrincipal, rootCert, userId, broadCap, expiration));
        }

        @ParameterizedTest
        @EnumSource(CapBACScheme.class)
        void testFail_InvokeWithBroaderCapability(CapBACScheme scheme) throws IOException {
            setupForScheme(scheme);
            CapBAC<StringCapability> api = new CapBAC<>(scheme, CODEC, CHECKER);

            Principal rootPrincipal = new Principal(bls, rootKeyPair);
            Principal intermediatePrincipal = new Principal(bls, intermediateKeyPair);
            Principal userPrincipal = new Principal(bls, userKeyPair);

            long expiration = Instant.now().getEpochSecond() + 3600;
            StringCapability readCap = new StringCapability("read");
            StringCapability fileCap = new StringCapability("read:/data/file.txt");
            StringCapability broadCap = new StringCapability("write");

            CapBACCertificate rootCert = api.forgeCertificate(rootPrincipal, intermediatePrincipal.getId(), readCap,
                    expiration);
            CapBACCertificate delegatedCert = api.delegateCertificate(intermediatePrincipal, rootCert,
                    userPrincipal.getId(), fileCap, expiration);

            assertThrows(IllegalArgumentException.class, () ->
                    api.invoke(userPrincipal, delegatedCert, broadCap, expiration));
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
