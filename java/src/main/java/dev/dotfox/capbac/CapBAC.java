package dev.dotfox.capbac;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSSignature;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CapBAC {
    private final CapBACScheme scheme;
    private final BLS bls;

    public CapBAC(CapBACScheme scheme) {
        this.scheme = scheme;
        this.bls = scheme.getBls();
    }

    public CapBACCertificate forgeCertificate(Principal issuer, byte[] subject, Capability capability,
            long expiration) {
        Certificate cert = new Certificate(issuer.getId(), subject, expiration, capability.toBytes());
        BLSSignature signature = issuer.sign(cert.toBytes());
        return new CapBACCertificate(scheme, Collections.singletonList(cert), signature);
    }

    public CapBACCertificate delegateCertificate(Principal issuer, CapBACCertificate originalToken, byte[] subject,
            Capability capability, long expiration) {
        if (originalToken.getCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Cannot delegate an empty certificate chain.");
        }

        Certificate lastCert = originalToken.getCertificateChain().get(originalToken.getCertificateChain().size() - 1);
        if (!java.util.Arrays.equals(lastCert.getSubject(), issuer.getId())) {
            throw new IllegalArgumentException("Issuer is not the subject of the last certificate in the chain.");
        }

        Certificate newCert = new Certificate(issuer.getId(), subject, expiration, capability.toBytes());
        BLSSignature newSignature = issuer.sign(newCert.toBytes());

        List<Certificate> newChain = new ArrayList<>(originalToken.getCertificateChain());
        newChain.add(newCert);

        BLSSignature aggregateSignature = bls
                .aggregate(java.util.Arrays.asList(originalToken.getAggregateSignature(), newSignature));

        return new CapBACCertificate(scheme, newChain, aggregateSignature);
    }

    public CapBACInvocation invoke(Principal invoker, CapBACCertificate originalToken, Capability capability,
            long expiration) {
        if (originalToken.getCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Cannot invoke an empty certificate chain.");
        }

        Certificate lastCert = originalToken.getCertificateChain().get(originalToken.getCertificateChain().size() - 1);
        if (!java.util.Arrays.equals(lastCert.getSubject(), invoker.getId())) {
            throw new IllegalArgumentException("Invoker is not the subject of the last certificate in the chain.");
        }

        Invocation invocation = new Invocation(invoker.getId(), expiration, capability.toBytes());
        BLSSignature invocationSignature = invoker.sign(invocation.toBytes());

        BLSSignature aggregateSignature = bls
                .aggregate(java.util.Arrays.asList(originalToken.getAggregateSignature(), invocationSignature));

        return new CapBACInvocation(scheme, originalToken.getCertificateChain(), invocation, aggregateSignature);
    }
}
