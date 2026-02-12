package dev.dotfox.bls;

import java.util.Base64;

import dev.dotfox.bls.impl.ByteCodec;
import dev.dotfox.bls.impl.Signature;

public class BLSSignature implements ByteCodec {
    private final Signature sig;

    public Signature getSignature() {
        return sig;
    }

    public BLSSignature(Signature sig) {
        this.sig = sig;
    }

    @Override
    public String toString() {
        return Base64.getEncoder().encodeToString(sig.toBytes());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((sig == null) ? 0 : sig.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        BLSSignature other = (BLSSignature) obj;
        if (sig == null) {
            if (other.sig != null)
                return false;
        } else if (!sig.equals(other.sig))
            return false;
        return true;
    }

    @Override
    public byte[] toBytes() {
        return sig.toBytes();
    }
}
