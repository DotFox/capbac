package dev.dotfox.capbac;

import java.util.Arrays;

public final class PrincipalId {
    private final byte[] data;

    public PrincipalId(byte[] data) {
        this.data = data.clone();
    }

    public byte[] toBytes() {
        return data.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrincipalId that = (PrincipalId) o;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
