package com.notronix.security;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public enum SecurityUtils
{
    INSTANCE;

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int HASH_KEY_SIZE = 256;
    private static final int HASH_SALT_SIZE = 128;
    private static final int HASH_ITERATIONS = 13666;

    private static final String WEAK_CIPHER_TYPE = "AES";
    private static final String WEAK_KEY_FACTORY = "PBKDF2WithHmacSHA1";
    private static final String WEAK_ENCRYPTION_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final int WEAK_ENCRYPTION_KEY_SIZE = 128;
    private static final int WEAK_ITERATIONS = 1000;

    public static HashResult hash(char[] message) throws GeneralSecurityException {
        byte[] salt = new byte[HASH_SALT_SIZE];
        new SecureRandom().nextBytes(salt);

        return hash(message, salt);
    }

    public static HashResult hash(char[] message, byte[] salt) throws GeneralSecurityException {
        return hash(message, salt, HASH_KEY_SIZE, HASH_ITERATIONS);
    }

    public static HashResult hash(char[] message, byte[] salt, int keySize, int iterations) throws GeneralSecurityException {
        PBEKeySpec keySpec;
        try {
            keySpec = new PBEKeySpec(message, salt, iterations, keySize * 8);
        }
        catch (NullPointerException | IllegalArgumentException ex) {
            throw new GeneralSecurityException("Encryption parameters are invalid.", ex);
        }

        SecretKeyFactory pbkdfKeyFactory;

        try {
            pbkdfKeyFactory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        }
        catch (NullPointerException | NoSuchAlgorithmException ex) {
            throw new GeneralSecurityException("Specified algorithm is invalid.");
        }

        byte[] hash;
        try {
            hash = pbkdfKeyFactory.generateSecret(keySpec).getEncoded();
        }
        catch (InvalidKeySpecException ex) {
            throw new GeneralSecurityException("key spec is invalid.", ex);
        }

        return new HashResult((new Base64()).encodeToString(hash), salt);
    }

    public static String encrypt(String message, String passPhrase) throws GeneralSecurityException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(WEAK_KEY_FACTORY);
            SecretKey secretKey = factory.generateSecret(new PBEKeySpec(passPhrase.toCharArray(),
                    passPhrase.getBytes(),
                    WEAK_ITERATIONS,
                    WEAK_ENCRYPTION_KEY_SIZE));
            SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), WEAK_CIPHER_TYPE);
            Cipher cipher = Cipher.getInstance(WEAK_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return new Base64().encodeAsString(cipher.doFinal(message.getBytes()));
        }
        catch (Exception ex) {
            throw new GeneralSecurityException("An error occurred trying to encrypt message.", ex);
        }
    }

    public static String decrypt(String encryptedMessage, String passPhrase) throws GeneralSecurityException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(WEAK_KEY_FACTORY);
            SecretKey secretKey = factory.generateSecret(new PBEKeySpec(passPhrase.toCharArray(),
                    passPhrase.getBytes(),
                    WEAK_ITERATIONS,
                    WEAK_ENCRYPTION_KEY_SIZE));
            SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), WEAK_CIPHER_TYPE);
            Cipher cipher = Cipher.getInstance(WEAK_ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);

            return new String(cipher.doFinal(Base64.decodeBase64(encryptedMessage)));
        }
        catch (Exception ex) {
            throw new GeneralSecurityException("An error occurred trying to decrypt message.", ex);
        }
    }
}
