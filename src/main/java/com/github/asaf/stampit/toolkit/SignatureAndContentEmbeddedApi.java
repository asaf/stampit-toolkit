package com.github.asaf.stampit.toolkit;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Sign content and produce an output stream that contains the content encoded in base64
 * with the signature embedded.
 */
public class SignatureAndContentEmbeddedApi {
    private static final String EOL = System.getProperty("line.separator");

    /**
     * Receive content as an input stream, sign the content with the given public key
     * and write the content and the signature embedded as base64 encoded.
     *
     * @param content
     * @param contentAndSignature
     * @return
     */
    public static OutputStream signAndEmbed(InputStream content, OutputStream contentAndSignature, PrivateKey privateKey) {
        try (BufferedInputStream bis = new BufferedInputStream(content)) {
            contentAndSignature.write(SignConfig.CONTENT_BEGIN.getBytes());
            contentAndSignature.write(EOL.getBytes());

            Signature signature = SignUtils.createSignatureForSigning(SignConfig.SIGNATURE_DEFAULT_ALGO, privateKey);
            //Dump the inputstream into the file
            byte[] buffer = new byte[1024];
            int len;
            while (bis.available() != 0) {
                len = bis.read(buffer);
                contentAndSignature.write(buffer, 0, len);
                signature.update(buffer, 0, len);
            }

            contentAndSignature.write(EOL.getBytes());
            contentAndSignature.write(SignConfig.CONTENT_END.getBytes());
            String sigStart = EOL + SignConfig.SIGNATURE_BEGIN + EOL;
            contentAndSignature.write(sigStart.getBytes());
            contentAndSignature.write(SignUtils.signContentAsBase64(signature).getBytes());
            String sigEnd = EOL + SignConfig.SIGNATURE_END;
            contentAndSignature.write(sigEnd.getBytes());
            contentAndSignature.close();

            return contentAndSignature;
        } catch (IOException | SignatureException e) {
            throw new SignException("Could not sign and embed content.", e);
        }
    }

    /**
     * Read embedded content and signature into the provided outputstreams
     *
     * @param signedContent An inputstream of the signed and content embedded encoded in base64
     * @param content       The outputstream to write the content to
     * @param signature     The outputstream to write the signature to
     */
    public static void readEmbeddedSigAndContent(InputStream signedContent, OutputStream content, OutputStream signature) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(signedContent))) {

            boolean inContent = false;
            String line;

            //Position reader in the start of the content
            while (br.ready() && !inContent) {
                line = br.readLine();
                if (line.equals(SignConfig.CONTENT_BEGIN)) {
                    inContent = true;
                }
            }

            //Read content
            while (br.ready() && inContent) {
                line = br.readLine();
                if (!line.equals(SignConfig.CONTENT_END)) {
                    content.write(line.getBytes());
                    content.write(EOL.getBytes());
                } else {
                    inContent = false;
                }
            }

            boolean isInSig = false;
            //Position reader in the start of the signature
            while (br.ready() && !isInSig) {
                line = br.readLine();
                if (line.equals(SignConfig.SIGNATURE_BEGIN)) {
                    isInSig = true;
                }
            }

            //Read signature
            while (br.ready() && isInSig) {
                line = br.readLine();
                if (!line.equals(SignConfig.SIGNATURE_END)) {
                    signature.write(line.getBytes());
                    signature.write(EOL.getBytes());
                } else {
                    isInSig = false;
                }
            }
        } catch (IOException e) {
            throw new SignException("Could not get signed and embedded content.", e);
        } finally {
            try {
                content.close();
                signature.close();
            } catch (IOException e) {
                throw new SignException("Could not get signed and embedded content.", e);
            }
        }
    }

    public static SignedContent loadAndVerifyEmbeddedSigAndContent(InputStream signedContent, PublicKey publicKey) {
        ByteArrayOutputStream contentBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream signatureBytes = new ByteArrayOutputStream();
        //read embedded content
        readEmbeddedSigAndContent(signedContent, contentBytes, signatureBytes);
        //decode base64 signature
        //TODO: Hack until we get ride of the \n at the end of every line
        String content = contentBytes.toString().substring(0, contentBytes.toString().length() - 1);
        String signature = signatureBytes.toString().substring(0, signatureBytes.toString().length() - 1);
        boolean verified = SignUtils.verifyData(new ByteArrayInputStream(content.getBytes()), SignConfig.SIGNATURE_DEFAULT_ALGO, publicKey, signature);
        if (!verified) {
            throw new SignException("Signature is not authentic.");
        }

        return new SignedContent(content, signature);
    }
}
