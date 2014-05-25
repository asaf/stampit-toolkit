package com.github.asaf.stampit.toolkit;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * License private key.
 */
public class SignPrivateKey {
    PrivateKey privateKey;

    /**
     * Load a {@link java.security.PrivateKey} from a base64 encoded string.
     *
     * @param pkString  The key in base64
     * @param algorithm The public key algorithm
     */
    public SignPrivateKey(String pkString, String algorithm) {
        try {
            privateKey = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pkString)));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new SignException("Could not create private key.", e);
        }
    }

    public PrivateKey getKey() {
        return privateKey;
    }
}
