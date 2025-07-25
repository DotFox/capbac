package dev.dotfox.capbac;

import java.io.IOException;
import java.util.List;

import dev.dotfox.bls.BLSSignature;

public interface CapBACToken {
    byte TYPE_CERTIFICATE = 0x01;
    byte TYPE_INVOCATION = 0x02;

    boolean verify(Resolver resolver, TrustChecker trustChecker);

    byte[] toBytes();

    CapBACScheme getScheme();

    List<Certificate> getCertificateChain();

    BLSSignature getAggregateSignature();

    static CapBACToken fromBytes(byte[] data) throws IOException {
        if (data == null || data.length == 0) {
            throw new IOException("Token data cannot be empty");
        }
        byte type = data[0];
        byte[] payload = new byte[data.length - 1];
        System.arraycopy(data, 1, payload, 0, payload.length);

        switch (type) {
            case TYPE_CERTIFICATE:
                return CapBACCertificate.fromBytesPayload(payload);
            case TYPE_INVOCATION:
                return CapBACInvocation.fromBytesPayload(payload);
            default:
                throw new IOException("Unknown token type: " + type);
        }
    }
}
