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
    private BLSSignature signature;

    public Certificate(byte[] issuer, byte[] subject, long expiration, byte[] capability) {
        this.issuer = issuer;
        this.subject = subject;
        this.expiration = expiration;
        this.capability = capability;
    }

    public byte[] getIssuer() {
        return issuer;
    }

    public byte[] getSubject() {
        return subject;
    }

    public long getExpiration() {
        return expiration;
    }

    public byte[] getRawCapability() {
        return capability;
    }

    public <T extends Capability> T getCapability(CapabilityCodec<T> codec) throws IOException {
        return codec.fromBytes(this.capability);
    }

    public BLSSignature getSignature() {
        return signature;
    }

    public void setSignature(BLSSignature signature) {
        this.signature = signature;
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

    public static Certificate fromBytes(DataInputStream dis) throws IOException {
        int issuerLength = dis.readInt();
        byte[] issuer = new byte[issuerLength];
        dis.readFully(issuer);

        int subjectLength = dis.readInt();
        byte[] subject = new byte[subjectLength];
        dis.readFully(subject);

        long expiration = dis.readLong();

        int capLength = dis.readInt();
        byte[] capBytes = new byte[capLength];
        dis.readFully(capBytes);

        return new Certificate(issuer, subject, expiration, capBytes);
    }
}
