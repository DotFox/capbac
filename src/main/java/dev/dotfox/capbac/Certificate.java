package dev.dotfox.capbac;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

public class Certificate {
    private final PrincipalId issuer;
    private final PrincipalId subject;
    private final long expiration;
    private final byte[] capability;

    public Certificate(PrincipalId issuer, PrincipalId subject, long expiration, byte[] capability) {
        this.issuer = issuer;
        this.subject = subject;
        this.expiration = expiration;
        this.capability = capability.clone();
    }

    public PrincipalId getIssuer() {
        return issuer;
    }

    public PrincipalId getSubject() {
        return subject;
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
            byte[] issuerBytes = issuer.toBytes();
            dos.writeInt(issuerBytes.length);
            dos.write(issuerBytes);
            byte[] subjectBytes = subject.toBytes();
            dos.writeInt(subjectBytes.length);
            dos.write(subjectBytes);
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

    public static Certificate fromBytes(DataInputStream dis) throws IOException {
        int issuerLength = readLength(dis);
        byte[] issuer = new byte[issuerLength];
        dis.readFully(issuer);

        int subjectLength = readLength(dis);
        byte[] subject = new byte[subjectLength];
        dis.readFully(subject);

        long expiration = dis.readLong();

        int capLength = readLength(dis);
        byte[] capBytes = new byte[capLength];
        dis.readFully(capBytes);

        return new Certificate(new PrincipalId(issuer), new PrincipalId(subject), expiration, capBytes);
    }
}
