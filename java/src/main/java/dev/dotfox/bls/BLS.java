package dev.dotfox.bls;

import java.util.List;
import java.util.stream.Collectors;

import dev.dotfox.bls.impl.BLS12381;
import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;

/**
 * An interface representing a specific BLS context (e.g., minimal-signature or
 * minimal-pubkey). It provides a contract for all BLS cryptographic operations.
 */
public interface BLS {
    BLSKeyPair keyGen();

    BLSSignature sign(BLSSecretKey sk, byte[] message);

    boolean verify(BLSPublicKey pk, byte[] message, BLSSignature signature);

    BLSSignature aggregate(List<? extends BLSSignature> signatures);

    boolean aggregateVerify(List<? extends BLSPublicKey> pks, List<byte[]> messages, BLSSignature sign);

    BLSSignature popProve(BLSSecretKey sk);

    boolean popVerify(BLSPublicKey pk, BLSSignature proof);

    BLSSignature signAugmented(BLSSecretKey sk, byte[] message);

    boolean aggregateVerifyAugmented(List<? extends BLSPublicKey> pks, List<byte[]> messages, BLSSignature sign);

    BLSSignature signatureFromBytes(byte[] payload);

    BLSPublicKey pkFromBytes(byte[] payload);

    BLSSecretKey skFromBytes(byte[] payload);
}

abstract class AbstractBLS implements BLS {

    protected abstract BLS12381 getImplementation();

    protected abstract int getPublicKeySize();

    protected abstract int getSignatureSize();

    protected abstract String getSchemeName();

    protected abstract PublicKey createPublicKey(byte[] payload);

    protected abstract SecretKey createSecretKey(byte[] payload);

    protected abstract Signature createSignature(byte[] payload);

    @Override
    public BLSKeyPair keyGen() {
        BLSSecretKey sk = new BLSSecretKey(getImplementation().keyGen());
        BLSPublicKey pk = new BLSPublicKey(getImplementation().skToPk(sk.getSk()));
        return new BLSKeyPair(sk, pk);
    }

    @Override
    public BLSSignature sign(BLSSecretKey sk, byte[] message) {
        return new BLSSignature(getImplementation().sign(sk.getSk(), message));
    }

    @Override
    public boolean verify(BLSPublicKey pk, byte[] message, BLSSignature signature) {
        return getImplementation().verify(pk.getPk(), message, signature.getSignature());
    }

    @Override
    public BLSSignature aggregate(List<? extends BLSSignature> signatures) {
        List<Signature> unwrappedSigs = signatures.stream()
                .map(BLSSignature::getSignature)
                .collect(Collectors.toList());
        return new BLSSignature(getImplementation().aggregate(unwrappedSigs));
    }

    @Override
    public boolean aggregateVerify(List<? extends BLSPublicKey> pks, List<byte[]> messages, BLSSignature sign) {
        List<PublicKey> unwrappedPks = pks.stream()
                .map(BLSPublicKey::getPk)
                .collect(Collectors.toList());
        return getImplementation().aggregateVerify(unwrappedPks, messages, sign.getSignature());
    }

    @Override
    public BLSSignature popProve(BLSSecretKey sk) {
        return new BLSSignature(getImplementation().popProve(sk.getSk()));
    }

    @Override
    public boolean popVerify(BLSPublicKey pk, BLSSignature proof) {
        return getImplementation().popVerify(pk.getPk(), proof.getSignature());
    }

    @Override
    public BLSSignature signAugmented(BLSSecretKey sk, byte[] message) {
        return new BLSSignature(getImplementation().signAugmented(sk.getSk(), message));
    }

    @Override
    public boolean aggregateVerifyAugmented(List<? extends BLSPublicKey> pks, List<byte[]> messages,
            BLSSignature sign) {
        List<PublicKey> unwrappedPks = pks.stream()
                .map(BLSPublicKey::getPk)
                .collect(Collectors.toList());
        return getImplementation().aggregateVerifyAugmented(unwrappedPks, messages, sign.getSignature());
    }

    @Override
    public BLSPublicKey pkFromBytes(byte[] payload) {
        if (payload.length != getPublicKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid public key length for " + getSchemeName() + ". Expected " + getPublicKeySize()
                            + " bytes, got " + payload.length);
        }
        return new BLSPublicKey(createPublicKey(payload));
    }

    @Override
    public BLSSignature signatureFromBytes(byte[] payload) {
        if (payload.length != getSignatureSize()) {
            throw new IllegalArgumentException(
                    "Invalid signature length for " + getSchemeName() + ". Expected " + getSignatureSize()
                            + " bytes, got " + payload.length);
        }
        return new BLSSignature(createSignature(payload));
    }

    @Override
    public BLSSecretKey skFromBytes(byte[] payload) {
        if (payload.length != 32) {
            throw new IllegalArgumentException(
                    "Invalid secret key length. Expected 32 bytes, got " + payload.length);
        }
        return new BLSSecretKey(createSecretKey(payload));
    }
}
