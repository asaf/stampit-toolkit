package com.github.asaf.stampit.toolkit;

/**
 * A model that contains a content and a signature
 */
public class SignedContent {
    private final String content;
    private final String signature;


    public SignedContent(String content, String signature) {
        this.content = content;
        this.signature = signature;
    }

    public String getContent() {
        return content;
    }

    public String getSignature() {
        return signature;
    }
}
