package com.github.asaf.stampit.toolkit;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Tests for the {@link SignUtils} class.
 */
public class SignUtilsTest {
    @Test
    public void generateKeyPairTest() {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 2048);
        assertThat(keyPair, notNullValue());
        assertThat(keyPair.getPrivate(), notNullValue());
        assertThat(keyPair.getPublic(), notNullValue());
    }

    @Test
    public void encodeKeyInBase64() {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        String encodedKey = SignUtils.encodeKeyInBase64(keyPair.getPublic());
        SignPublicKey loadedPublicKey = new SignPublicKey(encodedKey, SignConfig.KEYPAIR_DEFAULT_ALGO);
        assertThat(loadedPublicKey.getKey(), is(keyPair.getPublic()));
    }

    @Test
    public void encodePrivateKeyInBase64() {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        String encodedKey = SignUtils.encodeKeyInBase64(keyPair.getPrivate());
        SignPrivateKey loadedPrivateKey = new SignPrivateKey(encodedKey, SignConfig.KEYPAIR_DEFAULT_ALGO);
        assertThat(loadedPrivateKey.getKey(), is(keyPair.getPrivate()));
    }

    @Test
    public void createSignatureTest() {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        Signature signature = SignUtils.createSignatureForSigning(SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPrivate());
        assertThat(signature, notNullValue());
    }

    @Test
    public void signedContentAsBase64Test() throws SignatureException {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        Signature signature = SignUtils.createSignatureForSigning(SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPrivate());
        String content = "Some Secret";
        String signAndEncodedContent = SignUtils.signContentAsBase64(content, signature);
        assertThat(signAndEncodedContent, notNullValue());

        //Ensure validity of signed content
        InputStream is = new ByteArrayInputStream(content.getBytes());
        boolean signed = SignUtils.verifyData(is, SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPublic(), signAndEncodedContent);
        assertThat(signed, is(true));
    }

    @Test
    public void signAndVerifyDataTest() {
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        String content = "Some Secret";
        String signature = SignUtils.signData(new ByteArrayInputStream(content.getBytes()), SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPrivate());
        assertThat(signature, notNullValue());
        boolean verified = SignUtils.verifyData(new ByteArrayInputStream(content.getBytes()), SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPublic(), signature);
        assertThat(verified, is(true));
    }
}
