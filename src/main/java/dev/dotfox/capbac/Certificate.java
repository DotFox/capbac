package dev.dotfox.capbac;

import dev.dotfox.bls.BLSSignature;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Certificate {
    private final byte[] issuer;
    private final byte[] subject;
    private final long expiration;
    private final byte[] capability;

    public Certificate(byte[] issuer, byte[] subject, long expiration, byte[] capability) {
        this.issuer = issuer.clone();
        this.subject = subject.clone();
        this.expiration = expiration;
        this.capability = capability.clone();
    }

    public byte[] getIssuer() {
        return issuer.clone();
    }

    public byte[] getSubject() {
        return subject.clone();
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
            dos.writeInt(issuer.length);
            dos.write(issuer);
            dos.writeInt(subject.length);
            dos.write(subject);
            dos.writeLong(expiration);
            dos.writeInt(capability.length);
            dos.write(capability);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Error serializing certificate", e);
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

        return new Certificate(issuer, subject, expiration, capBytes);
    }
}
