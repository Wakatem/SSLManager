package wak.ssl;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class LocalCertificate {
    private PrivateKey privateKey;
    private char[] password;
    private Certificate[] chain;

    public LocalCertificate(PrivateKey privateKey, String password, Certificate[] chain){
        this.privateKey = privateKey;
        this.password = password.toCharArray();
        this.chain = chain;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public char[] getPassword() {
        return password;
    }

    public Certificate[] getChain() {
        return chain;
    }
}

