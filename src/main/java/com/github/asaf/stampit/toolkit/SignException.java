package com.github.asaf.stampit.toolkit;

/**
 * General exception related to digital signing errors.
 */
public class SignException extends RuntimeException {
    public SignException(String message) {
        super(message);
    }

    public SignException(String message, Throwable cause) {
        super(message, cause);
    }
}
