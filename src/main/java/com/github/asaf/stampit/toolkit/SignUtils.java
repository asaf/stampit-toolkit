package com.github.asaf.stampit.toolkit;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Utilities for signing digital content.
 */
public class SignUtils {

    /**
     * Generate a pair (public/private) of keys
     * <p>
     * With digital signing, the private key is used to sign the data while the corresponding public key
     * is freely distributed in the application installation and needed in order to verify the authenticity
     * of the signature.
     *
     * @param keyAlgorithm    The key algorithm, i.e "DSA"
     * @param randomAlgorithm The random algorithm, i.e "SHA1PRNG"
     * @param size            The size (in bits) of the key, i.e 1024
     * @return A {@link java.security.KeyPair} of keys.
     * @see #encodeKeyInBase64(java.security.Key)
     */
    public static KeyPair generateKeyPair(String keyAlgorithm, String randomAlgorithm, int size) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm, "SUN");
            SecureRandom random = SecureRandom.getInstance(randomAlgorithm, "SUN");
            keyGen.initialize(size, random);
            KeyPair pair = keyGen.generateKeyPair();
            return pair;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SignException("Could not generate key pair.", e);
        }
    }

    /**
     * Return the specified key encoded in base64.
     *
     * @param key The key to encode
     * @return base64 encoded key
     */
    public static String encodeKeyInBase64(Key key) {
        byte[] encodedKey = key.getEncoded();
        byte[] keyString = Base64.getEncoder().encode(encodedKey);

        try {
            return new String(keyString, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new SignException("Could not encode key in base64.", e);
        }
    }

    /**
     * Create a signature for the given private key for signing.
     * <p>
     * The signature is used to sign a some digital content.
     *
     * @param signatureAlgorithm The Signature algorithm, i.e "SHA1withDSA"
     * @param privateKey         The secret private key to sign the digital data with
     * @return a Signature instance
     */
    public static Signature createSignatureForSigning(String signatureAlgorithm, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm, "SUN");
            signature.initSign(privateKey);

            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new SignException("Could not init a signature for the specified algorithm and private key.", e);
        }
    }

    /**
     * Create a signature for verification with the given public key.
     * <p>
     * The signature is used to verify the authenticity of the signature.
     *
     * @param signatureAlgorithm The Signature algorithm, i.e "SHA1withDSA"
     * @param publicKey          The company public key to init the signature from
     * @return a Signature instance
     */
    public static Signature createSignatureForVerify(String signatureAlgorithm, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm, "SUN");
            signature.initVerify(publicKey);

            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new SignException("Could not init a signature for the specified algorithm and public key.", e);
        }
    }

    /**
     * Sign the provided signature and return the signed content encoded in base64
     *
     * @param signature The signature to sign and base64 encode
     * @return base64 encoded signed content
     */
    public static String signContentAsBase64(Signature signature) {
        try {
            return new String(Base64.getEncoder().encode(signature.sign()), "UTF-8");
        } catch (UnsupportedEncodingException | SignatureException e) {
            throw new SignException("Could not sign and base64 encode the provided signature.", e);
        }
    }

    public static String signContentAsBase64(String content, Signature signature) {
        try {
            signature.update(content.getBytes());
            return signContentAsBase64(signature);
        } catch (SignatureException e) {
            throw new SignException("Could not sign and base64 encode the provided signature.", e);
        }
    }

    /**
     * Signs digital content.
     *
     * @param digitalContentInputStream An input stream of the digital content to sign.
     * @param signatureAlgorithm        The Signature algorithm, i.e "SHA1withDSA"
     * @param privateKey                The secret private key to sign the digital data with
     * @return The signature of the digital content encoded in base64
     */
    public static String signData(InputStream digitalContentInputStream, String signatureAlgorithm, PrivateKey privateKey) {
        Signature signature = createSignatureForSigning(signatureAlgorithm, privateKey);

        byte[] buffer = new byte[1024];
        int len;
        try (BufferedInputStream bis = new BufferedInputStream((digitalContentInputStream))) {
            while ((len = bis.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
            }

            //Generate the digital signature once all data has been supplied to the Signature object.
            return new String(Base64.getEncoder().encode(signature.sign()));
        } catch (IOException | SignatureException e) {
            throw new SignException("Could not sign data", e);
        }
    }

    /**
     * Verify the authenticity of the signature,
     * <p>
     * For this process we need:
     * - The data
     * - the signature
     * - the public key corresponding to the private key used to sign the data.
     *
     * @param digitalContentInputStream An input stream of the digital content to verify.
     * @param signatureAlgorithm        The Signature algorithm, i.e "SHA1withDSA"
     * @param publicKey                 The public key corresponding to the private key used to sign the data
     * @param sigInBase64               the signature encoded in base64
     * @return true if the signature was successfully verified for the corresponding data.
     */
    public static boolean verifyData(InputStream digitalContentInputStream, String signatureAlgorithm, PublicKey publicKey, String sigInBase64) {
        Signature signature = createSignatureForVerify(signatureAlgorithm, publicKey);
        byte[] buffer = new byte[1024];
        int len;
        try (BufferedInputStream bis = new BufferedInputStream(digitalContentInputStream)) {
            while (bis.available() != 0) {
                len = bis.read(buffer);
                signature.update(buffer, 0, len);
            }

            //Verify the digital signature of that data and report the result once all data supplied to the Signature
            return signature.verify(Base64.getDecoder().decode(sigInBase64.getBytes()));
        } catch (IOException | SignatureException e) {
            throw new SignException("Could not sign data", e);
        }
    }
}
