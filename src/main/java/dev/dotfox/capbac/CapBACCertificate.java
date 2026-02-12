package dev.dotfox.capbac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import dev.dotfox.bls.BLSPublicKey;
import dev.dotfox.bls.BLSSignature;

public class CapBACCertificate implements CapBACToken {
    private final CapBACScheme scheme;
    private final List<Certificate> certificateChain;
    private final BLSSignature aggregateSignature;

    public CapBACCertificate(CapBACScheme scheme, List<Certificate> certificateChain, BLSSignature aggregateSignature) {
        this.scheme = scheme;
        this.certificateChain = new ArrayList<>(certificateChain);
        this.aggregateSignature = aggregateSignature;
    }

    @Override
    public <T extends Capability> boolean verify(Resolver resolver, TrustChecker trustChecker,
            CapabilityCodec<T> codec, AttenuationChecker<T> checker) throws IOException {
        // 1. Check expiration
        long now = Instant.now().getEpochSecond();
        if (certificateChain.stream().anyMatch(c -> c.getExpiration() < now)) {
            return false;
        }

        // 2. Check trust anchor
        if (certificateChain.isEmpty() || !trustChecker.check(certificateChain.get(0).getIssuer())) {
            return false;
        }

        // 3. Verify delegation chain
        for (int i = 0; i < certificateChain.size() - 1; i++) {
            if (!certificateChain.get(i).getSubject().equals(certificateChain.get(i + 1).getIssuer())) {
                return false;
            }
        }

        // 3b. Verify attenuation
        for (int i = 0; i < certificateChain.size() - 1; i++) {
            T parentCap = certificateChain.get(i).getCapability(codec);
            T childCap = certificateChain.get(i + 1).getCapability(codec);
            if (!checker.isValidAttenuation(parentCap, childCap)) {
                return false;
            }
        }

        // 4. Verify aggregate signature
        List<BLSPublicKey> publicKeys = new ArrayList<>();
        List<byte[]> messages = new ArrayList<>();

        for (Certificate cert : certificateChain) {
            Optional<BLSPublicKey> pk = resolver.resolve(cert.getIssuer());
            if (pk.isEmpty()) {
                return false;
            }
            publicKeys.add(pk.get());
            messages.add(cert.toBytes());
        }

        return scheme.getBls().aggregateVerify(publicKeys, messages, aggregateSignature);
    }

    @Override
    public byte[] toBytes() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(bos)) {
            dos.writeByte(TYPE_CERTIFICATE);
            dos.writeByte(scheme.getId());
            dos.writeInt(certificateChain.size());
            for (Certificate cert : certificateChain) {
                byte[] certBytes = cert.toBytes();
                dos.writeInt(certBytes.length);
                dos.write(certBytes);
            }
            byte[] sigBytes = aggregateSignature.getSignature().toBytes();
            dos.write(sigBytes);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int readLength(DataInputStream dis) throws IOException {
        int length = dis.readInt();
        if (length < 0 || length > dis.available()) {
            throw new IOException("Invalid length: " + length);
        }
        return length;
    }

    public static CapBACCertificate fromBytesPayload(byte[] data) throws IOException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
                DataInputStream dis = new DataInputStream(bis)) {
            CapBACScheme scheme = CapBACScheme.fromId(dis.readByte());

            int certChainSize = readLength(dis);
            List<Certificate> certificateChain = new ArrayList<>(certChainSize);
            for (int i = 0; i < certChainSize; i++) {
                int certSize = readLength(dis);
                byte[] certBytes = new byte[certSize];
                dis.readFully(certBytes);
                certificateChain.add(Certificate.fromBytes(new DataInputStream(new ByteArrayInputStream(certBytes))));
            }

            int sigSize = scheme.getSignatureSize();
            byte[] sigBytes = new byte[sigSize];
            dis.readFully(sigBytes);

            if (dis.available() > 0) {
                throw new IOException("Extra bytes at the end of certificate token data");
            }

            BLSSignature signature = scheme.getBls().signatureFromBytes(sigBytes);
            return new CapBACCertificate(scheme, certificateChain, signature);
        }
    }

    @Override
    public CapBACScheme getScheme() {
        return scheme;
    }

    @Override
    public List<Certificate> getCertificateChain() {
        return Collections.unmodifiableList(certificateChain);
    }

    @Override
    public BLSSignature getAggregateSignature() {
        return aggregateSignature;
    }
}
