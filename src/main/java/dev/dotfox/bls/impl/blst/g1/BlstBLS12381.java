package dev.dotfox.bls.impl.blst.g1;

import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;
import dev.dotfox.bls.impl.blst.AbstractBlstBLS12381;
import supranational.blst.BLST_ERROR;
import supranational.blst.Pairing;

// This class now only contains the logic specific to the G1 scheme.
public class BlstBLS12381 extends AbstractBlstBLS12381 {

    private static final String CIPHERSUITE = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    private static final String POP_CIPHERSUITE = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    @Override
    protected String getCiphersuite() {
        return CIPHERSUITE;
    }

    @Override
    protected String getPopCiphersuite() {
        return POP_CIPHERSUITE;
    }

    @Override
    protected SecretKey createSecretKey(supranational.blst.SecretKey sk) {
        return new BlstSecretKey(sk);
    }

    @Override
    public BlstPublicKey skToPk(SecretKey sk) {
        return ((BlstSecretKey) sk).derivePublicKey();
    }

    @Override
    public BlstSignature sign(SecretKey sk, byte[] message) {
        return signWithDst(sk, message, getCiphersuite());
    }

    @Override
    protected BlstSignature signWithDst(SecretKey sk, byte[] message, String dst) {
        return ((BlstSecretKey) sk).sign(message, dst);
    }

    @Override
    protected BLST_ERROR doAggregate(Pairing ctx, PublicKey pk, Signature sig, byte[] message) {
        BlstPublicKey blstPk = (BlstPublicKey) pk;
        BlstSignature blstSig = (BlstSignature) sig;
        return ctx.aggregate(blstPk.point, blstSig != null ? blstSig.point : null, message, new byte[0]);
    }
}
