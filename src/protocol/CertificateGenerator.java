package protocol;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import java.util.concurrent.TimeUnit;

public class CertificateGenerator {

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
        return generator.generateKeyPair();

    }


    //self-signed generated certificate
    public X509Certificate generateCertificate(String signatureAlgorithm, SecureRandom random, KeyPair keyPair, String commonName, int duration){

        Date notBefore=getDates(duration)[0];
        Date notAfter = getDates(duration)[1];
        X500Name user = new X500Name("CN="+commonName);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(user, new BigInteger(64, random), notBefore, notAfter, user, keyInfo);

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
    public X509Certificate generateCertificate(String signatureAlgorithm, SecureRandom random, KeyPair subjectKeyPair, String subjectCommonName, String issuerCommonName, PrivateKey CAkey, int duration){

        Date notBefore=getDates(duration)[0];
        Date notAfter = getDates(duration)[1];
        X500Name subject = new X500Name("CN="+subjectCommonName);
        X500Name CA = new X500Name("CN="+issuerCommonName);
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(subjectKeyPair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(CA, new BigInteger(64, random), notBefore, notAfter, subject, keyInfo);

        //create signer
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = null;
        X509Certificate certificate = null;

        try {
            signer = signerBuilder.build(CAkey);
            X509CertificateHolder holder = builder.build(signer);
            certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return certificate;
    }

    private Date[] getDates(int duration){

        Date notBefore = new Date(System.currentTimeMillis());
        long afterValue = TimeUnit.DAYS.toMillis(duration) + notBefore.getTime();
        Date notAfter = new Date(afterValue);

        return new Date[]{notBefore, notAfter};
    }

}
