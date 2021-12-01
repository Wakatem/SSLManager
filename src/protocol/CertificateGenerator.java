package protocol;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateGenerator {
    private KeyPair keyPair;

    public CertificateGenerator(){}

    public KeyPair generateKeyPair(String algorithm, int keySize, SecureRandom random){
        KeyPairGenerator generator;

        try {
            generator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        generator.initialize(keySize, random);
        keyPair = generator.generateKeyPair();

        return keyPair;
    }


    //self-signed generated certificate
    public X509Certificate generateCertificate(String signatureAlgorithm, SecureRandom random, String commonName, int duration){

        Date notBefore=null;
        Date notAfter = null;
        X500Name user = new X500Name("CN="+commonName);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(user, new BigInteger(64, random), notBefore, notAfter, user, (SubjectPublicKeyInfo) keyPair.getPublic());

        //create signer
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        X509Certificate certificate = null;

        try {
            signer = signerBuilder.build(keyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return certificate;
    }

    //issuer-based generated certificate
    public X509Certificate generateCertificate(String signatureAlgorithm, SecureRandom random, String subjectCommonName, String issuerCommonName, PublicKey CAkey, int duration){

        Date notBefore=null;
        Date notAfter = null;
        X500Name user = new X500Name("CN="+subjectCommonName);
        X500Name CA = new X500Name("CN="+issuerCommonName);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(user, new BigInteger(64, random), notBefore, notAfter, CA, (SubjectPublicKeyInfo) CAkey);

        //create signer
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        X509Certificate certificate = null;

        try {
            signer = signerBuilder.build(keyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return certificate;
    }

    private Date[] getDates(Date duration){

        return null;
    }

}
