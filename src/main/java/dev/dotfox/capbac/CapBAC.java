package dev.dotfox.capbac;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSSignature;

public class CapBAC<T extends Capability> {
    private final CapBACScheme scheme;
    private final BLS bls;
    private final CapabilityCodec<T> codec;
    private final AttenuationChecker<T> checker;

    public CapBAC(CapBACScheme scheme, CapabilityCodec<T> codec, AttenuationChecker<T> checker) {
        this.scheme = Objects.requireNonNull(scheme, "scheme");
        this.bls = scheme.getBls();
        this.codec = Objects.requireNonNull(codec, "codec");
        this.checker = Objects.requireNonNull(checker, "checker");
    }

    public CapBACCertificate forgeCertificate(Principal issuer, byte[] subject, T capability,
            long expiration) {
        Certificate cert = new Certificate(issuer.getId(), subject, expiration, capability.toBytes());
        BLSSignature signature = issuer.sign(cert.toBytes());
        return new CapBACCertificate(scheme, Collections.singletonList(cert), signature);
    }

    public CapBACCertificate delegateCertificate(Principal issuer, CapBACCertificate originalToken, byte[] subject,
            T capability, long expiration) throws IOException {
        if (originalToken.getCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Cannot delegate an empty certificate chain.");
        }

        Certificate lastCert = originalToken.getCertificateChain().get(originalToken.getCertificateChain().size() - 1);
        if (!java.util.Arrays.equals(lastCert.getSubject(), issuer.getId())) {
            throw new IllegalArgumentException("Issuer is not the subject of the last certificate in the chain.");
        }

        T parentCap = lastCert.getCapability(codec);
        if (!checker.isValidAttenuation(parentCap, capability)) {
            throw new IllegalArgumentException("Capability is not a valid attenuation of the parent capability.");
        }

        Certificate newCert = new Certificate(issuer.getId(), subject, expiration, capability.toBytes());
        BLSSignature newSignature = issuer.sign(newCert.toBytes());

        List<Certificate> newChain = new ArrayList<>(originalToken.getCertificateChain());
        newChain.add(newCert);

        BLSSignature aggregateSignature = bls
                .aggregate(java.util.Arrays.asList(originalToken.getAggregateSignature(), newSignature));

        return new CapBACCertificate(scheme, newChain, aggregateSignature);
    }

    public CapBACInvocation invoke(Principal invoker, CapBACCertificate originalToken, T capability,
            long expiration) throws IOException {
        if (originalToken.getCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Cannot invoke an empty certificate chain.");
        }

        Certificate lastCert = originalToken.getCertificateChain().get(originalToken.getCertificateChain().size() - 1);
        if (!java.util.Arrays.equals(lastCert.getSubject(), invoker.getId())) {
            throw new IllegalArgumentException("Invoker is not the subject of the last certificate in the chain.");
        }

        T lastCertCap = lastCert.getCapability(codec);
        if (!checker.isValidAttenuation(lastCertCap, capability)) {
            throw new IllegalArgumentException("Capability is not a valid attenuation of the last certificate capability.");
        }

        Invocation invocation = new Invocation(invoker.getId(), expiration, capability.toBytes());
        BLSSignature invocationSignature = invoker.sign(invocation.toBytes());

        BLSSignature aggregateSignature = bls
                .aggregate(java.util.Arrays.asList(originalToken.getAggregateSignature(), invocationSignature));

        List<Certificate> newChain = new ArrayList<>(originalToken.getCertificateChain());
        return new CapBACInvocation(scheme, newChain, invocation, aggregateSignature);
    }
}
