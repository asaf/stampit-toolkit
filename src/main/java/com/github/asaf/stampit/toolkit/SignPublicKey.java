package com.github.asaf.stampit.toolkit;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * License public key.
 */
public class SignPublicKey {
    PublicKey publicKey;

    /**
     * Load a {@link java.security.PublicKey} from a base64 encoded string.
     *
     * @param pkString  The key in base64
     * @param algorithm The public key algorithm
     */
    public SignPublicKey(String pkString, String algorithm) {
        try {
            publicKey = KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pkString)));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new SignException("Could not create public key.", e);
        }
    }

    public PublicKey getKey() {
        return publicKey;
    }
}
