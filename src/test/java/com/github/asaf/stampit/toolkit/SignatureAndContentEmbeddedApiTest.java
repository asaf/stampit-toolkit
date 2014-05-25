package com.github.asaf.stampit.toolkit;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Tests for {@link SignatureAndContentEmbeddedApi}
 */
public class SignatureAndContentEmbeddedApiTest {
    @Test
    public void signAndEmbedTest() throws SignatureException {
        //Embed
        KeyPair keyPair = SignUtils.generateKeyPair(SignConfig.KEYPAIR_DEFAULT_ALGO, SignConfig.STRONG_RANDOM_DEFAULT_ALGO, 1024);
        String content = "This is my content";
        InputStream inputStream = new ByteArrayInputStream(content.getBytes());
        ByteArrayOutputStream embeddedByteArray = new ByteArrayOutputStream();
        SignatureAndContentEmbeddedApi.signAndEmbed(inputStream, embeddedByteArray, keyPair.getPrivate());

        //Read
        ByteArrayOutputStream signatureByteArray = new ByteArrayOutputStream();
        ByteArrayOutputStream contentByteArray = new ByteArrayOutputStream();
        SignatureAndContentEmbeddedApi.readEmbeddedSigAndContent(new ByteArrayInputStream(embeddedByteArray.toByteArray()), contentByteArray, signatureByteArray);
        //TODO: Hack to remove \n from string as it's added by the verifyAndGetSignedContent method
        assertThat(contentByteArray.toString().replace("\n", ""), is(content));

        Signature signature = SignUtils.createSignatureForVerify(SignConfig.SIGNATURE_DEFAULT_ALGO, keyPair.getPublic());
        signature.update(content.getBytes());

        //Verify and read as SignedContent
        SignedContent signedContent = SignatureAndContentEmbeddedApi.loadAndVerifyEmbeddedSigAndContent(new ByteArrayInputStream(embeddedByteArray.toByteArray()), keyPair.getPublic());
        assertThat(signedContent.getContent(), is(content));
        assertThat(signedContent.getSignature(), notNullValue());
    }
}
