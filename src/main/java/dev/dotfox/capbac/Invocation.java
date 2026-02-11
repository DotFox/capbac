package dev.dotfox.capbac;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Invocation {
    private final byte[] invoker;
    private final long expiration;
    private final byte[] capability;

    public Invocation(byte[] invoker, long expiration, byte[] capability) {
        this.invoker = invoker.clone();
        this.expiration = expiration;
        this.capability = capability.clone();
    }

    public byte[] getInvoker() {
        return invoker.clone();
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
            dos.writeInt(invoker.length);
            dos.write(invoker);
            dos.writeLong(expiration);
            dos.writeInt(capability.length);
            dos.write(capability);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error serializing invocation", e);
        }
    }

    public static Invocation fromBytes(DataInputStream dis) throws IOException {
        int invokerLength = dis.readInt();
        byte[] invoker = new byte[invokerLength];
        dis.readFully(invoker);

        long expiration = dis.readLong();

        int capLength = dis.readInt();
        byte[] capBytes = new byte[capLength];
        dis.readFully(capBytes);

        return new Invocation(invoker, expiration, capBytes);
    }
}
