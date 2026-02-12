package dev.dotfox.capbac;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

public class Invocation {
    private final PrincipalId invoker;
    private final long expiration;
    private final byte[] capability;

    public Invocation(PrincipalId invoker, long expiration, byte[] capability) {
        this.invoker = invoker;
        this.expiration = expiration;
        this.capability = capability.clone();
    }

    public PrincipalId getInvoker() {
        return invoker;
    }

    public long getExpiration() {
        return expiration;
    }

    public byte[] getRawCapability() {
        return capability.clone();
    }

    public <T extends Capability> T getCapability(CapabilityCodec<T> codec) throws IOException {
        return codec.fromBytes(this.capability);
    }

    public byte[] toBytes() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(bos)) {
            byte[] invokerBytes = invoker.toBytes();
            dos.writeInt(invokerBytes.length);
            dos.write(invokerBytes);
            dos.writeLong(expiration);
            dos.writeInt(capability.length);
            dos.write(capability);
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

    public static Invocation fromBytes(DataInputStream dis) throws IOException {
        int invokerLength = readLength(dis);
        byte[] invoker = new byte[invokerLength];
        dis.readFully(invoker);

        long expiration = dis.readLong();

        int capLength = readLength(dis);
        byte[] capBytes = new byte[capLength];
        dis.readFully(capBytes);

        return new Invocation(new PrincipalId(invoker), expiration, capBytes);
    }
}
