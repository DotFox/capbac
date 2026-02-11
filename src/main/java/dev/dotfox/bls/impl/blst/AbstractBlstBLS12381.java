package dev.dotfox.bls.impl.blst;

import dev.dotfox.bls.impl.BLS12381;
import dev.dotfox.bls.impl.BlsException;
import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;
import supranational.blst.BLST_ERROR;
import supranational.blst.Pairing;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public abstract class AbstractBlstBLS12381 implements BLS12381 {
    private static final SecureRandom RND = new SecureRandom();

    // Abstract methods to be implemented by subclasses
    protected abstract String getCiphersuite();

    protected abstract SecretKey createSecretKey(supranational.blst.SecretKey sk);

    public abstract PublicKey skToPk(SecretKey sk);

    public abstract Signature sign(SecretKey sk, byte[] message);

    protected abstract BLST_ERROR doAggregate(Pairing ctx, PublicKey pk, Signature sig, byte[] message);

    private static Random getRND() {
        return RND;
    }

    @Override
    public SecretKey keyGen() {
        byte[] ikm = new byte[128];
        getRND().nextBytes(ikm);
        supranational.blst.SecretKey sk = new supranational.blst.SecretKey();
        sk.keygen(ikm);
        return createSecretKey(sk);
    }

    @Override
    public boolean keyValidate(PublicKey pk) {
        return pk.isValid();
    }

    @Override
    public boolean verify(PublicKey pk, byte[] message, Signature signature) {
        supranational.blst.P1_Affine sigP1 = signature instanceof dev.dotfox.bls.impl.blst.g1.BlstSignature
                ? ((dev.dotfox.bls.impl.blst.g1.BlstSignature) signature).getPoint()
                : null;
        supranational.blst.P2_Affine sigP2 = signature instanceof dev.dotfox.bls.impl.blst.g2.BlstSignature
                ? ((dev.dotfox.bls.impl.blst.g2.BlstSignature) signature).getPoint()
                : null;

        supranational.blst.P1_Affine pkP1 = pk instanceof dev.dotfox.bls.impl.blst.g2.BlstPublicKey
                ? ((dev.dotfox.bls.impl.blst.g2.BlstPublicKey) pk).getPoint()
                : null;
        supranational.blst.P2_Affine pkP2 = pk instanceof dev.dotfox.bls.impl.blst.g1.BlstPublicKey
                ? ((dev.dotfox.bls.impl.blst.g1.BlstPublicKey) pk).getPoint()
                : null;

        if (sigP1 != null && pkP2 != null) {
            return sigP1.core_verify(pkP2, true, message, getCiphersuite()) == BLST_ERROR.BLST_SUCCESS;
        }
        if (sigP2 != null && pkP1 != null) {
            return sigP2.core_verify(pkP1, true, message, getCiphersuite()) == BLST_ERROR.BLST_SUCCESS;
        }
        throw new BlsException("Type mismatch between public key and signature for verification.");
    }

    @Override
    public Signature aggregate(List<? extends Signature> signatures) {
        if (signatures.isEmpty()) {
            throw new BlsException("Signature list cannot be empty for aggregation.");
        }
        // Assuming all signatures are of the same type.
        if (signatures.get(0) instanceof dev.dotfox.bls.impl.blst.g1.BlstSignature) {
            return dev.dotfox.bls.impl.blst.g1.BlstSignature.aggregate(
                    signatures.stream().map(s -> (dev.dotfox.bls.impl.blst.g1.BlstSignature) s)
                            .collect(Collectors.toList()));
        }
        return dev.dotfox.bls.impl.blst.g2.BlstSignature.aggregate(
                signatures.stream().map(s -> (dev.dotfox.bls.impl.blst.g2.BlstSignature) s)
                        .collect(Collectors.toList()));
    }

    @Override
    public boolean aggregateVerify(List<? extends PublicKey> pks, List<byte[]> messages, Signature signature) {
        if (pks.size() != messages.size()) {
            return false;
        }
        if (messages.stream().map(ByteBuffer::wrap).distinct().count() < messages.size()) {
            return false;
        }

        Pairing ctx = new Pairing(true, getCiphersuite());
        for (int i = 0; i < pks.size(); i++) {
            BLST_ERROR ret = doAggregate(ctx, pks.get(i), i == 0 ? signature : null, messages.get(i));
            if (ret != BLST_ERROR.BLST_SUCCESS) {
                throw new BlsException("Error in Blst: " + ret);
            }
        }
        ctx.commit();
        return ctx.finalverify();
    }

    @Override
    public Signature popProve(SecretKey sk) {
        PublicKey pk = skToPk(sk);
        return sign(sk, pk.toBytes());
    }

    @Override
    public boolean popVerify(PublicKey pk, Signature proof) {
        return verify(pk, pk.toBytes(), proof);
    }

    @Override
    public Signature signAugmented(SecretKey sk, byte[] message) {
        PublicKey pk = skToPk(sk);
        byte[] pkBytes = pk.toBytes();
        byte[] augmentedMessage = new byte[pkBytes.length + message.length];
        System.arraycopy(pkBytes, 0, augmentedMessage, 0, pkBytes.length);
        System.arraycopy(message, 0, augmentedMessage, pkBytes.length, message.length);
        return sign(sk, augmentedMessage);
    }

    @Override
    public boolean aggregateVerifyAugmented(List<? extends PublicKey> pks, List<byte[]> messages, Signature signature) {
        if (pks.size() != messages.size()) {
            return false;
        }
        List<byte[]> augmentedMessages = new ArrayList<>(pks.size());
        for (int i = 0; i < pks.size(); i++) {
            byte[] pkBytes = pks.get(i).toBytes();
            byte[] msg = messages.get(i);
            byte[] augmentedMessage = new byte[pkBytes.length + msg.length];
            System.arraycopy(pkBytes, 0, augmentedMessage, 0, pkBytes.length);
            System.arraycopy(msg, 0, augmentedMessage, pkBytes.length, msg.length);
            augmentedMessages.add(augmentedMessage);
        }
        return aggregateVerify(pks, augmentedMessages, signature);
    }
}
