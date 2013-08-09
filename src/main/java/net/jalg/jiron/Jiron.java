package net.jalg.jiron;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import net.jalg.jiron.util.Base64;

/**
 * @author Jan Algermissen, http://www.jalg.net
 * 
 */
public class Jiron {

	/**
	 * Algorithm to use for generating encryption and integrity keys.
	 */
	private static final String KEYGEN_ALGORITHM = "PBKDF2WithHmacSHA1";

	/**
	 * Delimiter of parts of sealed token.
	 */
	private static final String DELIM = "*";

	/**
	 * Delimiter regex for splitting token.
	 */
	private static final String DELIM_SPLIT_REGEX = "\\*";

	/**
	 * Iron mac format version.
	 */
	private static final String MAC_FORMAT_VERSION = "1";
	/**
	 * Iron mac prefix.
	 */
	private static final String MAC_PREFIX = "Fe26." + MAC_FORMAT_VERSION;

	/**
	 * The algorithms supported by Jiron.
	 * 
	 * @author Jan Algermissen, http://www.jalg.net
	 * 
	 */
	public static enum Algorithm {

		/**
		 * AES-128-CBC
		 * 
		 * Has a key length of 128 bits. IV length of 128 bits is fixed for CBC.
		 * <p>
		 * Used for encryption.
		 * </p>
		 * 
		 */
		AES_128_CBC("aes-128-cbc", "AES/CBC/PKCS5PADDING", 128, 128),

		/**
		 * AES-256-CBC
		 * 
		 * Has a key length of 256 bits. IV length of 128 bits is fixed for CBC.
		 * (To use this, you need to install the unlimited strength juristiction
		 * policy files. See <a href=
		 * "https://github.com/algermissen/jiron#256bit-aes-keys-and-unlimited-strength-jurisdiction-policy-files"
		 * > Jiron README</a>.
		 * <p>
		 * Used for encryption.
		 * </p>
		 * 
		 */
		AES_256_CBC("aes-256-cbc", "AES/CBC/PKCS5PADDING", 256, 128),

		/**
		 * SHA-256
		 * 
		 * Used for integrity verification.
		 * 
		 */
		SHA_256("sha256", "HmacSHA256", 256, 0);

		private final String name;
		protected final String transformation;
		protected final int keyBits;
		protected final int ivBits;

		private Algorithm(final String name, final String transformation,
				final int keyBits, final int ivBits) {
			this.name = name;
			this.transformation = transformation;
			this.keyBits = keyBits;
			this.ivBits = ivBits;
		}

		public String getName() {
			return name;
		}
	}

	/**
	 * Options for encryption or integrity.
	 * 
	 * @author Jan Algermissen, http://www.jalg.net
	 * 
	 */
	public static class Options {
		public final int saltBits;
		public final Algorithm algorithm;
		public final int iterations;

		/**
		 * Instantiate options.
		 * 
		 * @param saltBits
		 *            Size of salt in bits.
		 * @param algorithm
		 *            Algorithm to use.
		 * @param iterations
		 *            Number of iterations to use.
		 */
		public Options(int saltBits, Algorithm algorithm, int iterations) {
			this.saltBits = saltBits;
			this.algorithm = algorithm;
			this.iterations = iterations;
		}
	}

	/**
	 * Default encryption options.
	 * 
	 * Use AES 256 CBC with a salt size of 256 bits and 1 iteration for
	 * encryption key generation.
	 * 
	 */
	public static Options DEFAULT_ENCRYPTION_OPTIONS = new Options(256,
			Algorithm.AES_256_CBC, 1);

	/**
	 * Default integrity options.
	 * 
	 * Use SHA 256 with a salt size of 256 bits and 1 iteration for integrity
	 * key generation.
	 */
	public static Options DEFAULT_INTEGRITY_OPTIONS = new Options(256,
			Algorithm.SHA_256, 1);

	/**
	 * Seal data into an encapsulated token.
	 * 
	 * This method takes the input data and produces an encapsulated token.
	 * 
	 * @param data
	 *            The data to encapsulate.
	 * @param password
	 *            Symmetric password for sealing and unsealing the data.
	 * @param encryptionOptions
	 *            Parameters used for the encryption phase.
	 * @param integrityOptions
	 *            Parameters used for the integrity phase.
	 * @return The encapsulated token.
	 * @throws JironException
	 */
	public static String seal(String data, String password,
			Options encryptionOptions, Options integrityOptions)
			throws JironException {
		return seal(data,null,password,encryptionOptions,integrityOptions);
	}
	
	/**
	 * Seal data into an encapsulated token.
	 * 
	 * This method takes the input data and produces an encapsulated token.
	 * 
	 * @param data
	 *            The data to encapsulate.
	 * @param passwordId
	 *            Id of the supplied password when using password rotation
	 * @param password
	 *            Symmetric password for sealing and unsealing the data.
	 * @param encryptionOptions
	 *            Parameters used for the encryption phase.
	 * @param integrityOptions
	 *            Parameters used for the integrity phase.
	 * @return The encapsulated token.
	 * @throws JironException
	 */
	public static String seal(String data, String passwordId, String password,
			Options encryptionOptions, Options integrityOptions)
			throws JironException {

		char[] charPassword = new char[password.length()];
		password.getChars(0, password.length(), charPassword, 0);
		
		/*
		 * Generate encryption salt, iv and key.
		 */

		// Salt contains only 0-9A-F chars and is 'token-ready'.
		String encryptionSaltString = generateSalt(encryptionOptions.saltBits);
		byte[] encryptionSalt = encryptionSaltString
				.getBytes(StandardCharsets.UTF_8);
		byte[] encryptionIv = generateIv(encryptionOptions.algorithm.ivBits);
		SecretKey encryptionSecretKey = generateKey(charPassword,
				encryptionSalt, encryptionOptions.algorithm,
				encryptionOptions.iterations);

		/*
		 * Encrypt
		 */

		byte[] encryptedData = encrypt(data.getBytes(StandardCharsets.UTF_8),
				encryptionOptions.algorithm, encryptionSecretKey, encryptionIv);

		/**
		 * Prepare for token and create HMAC base string.
		 */

		String encryptedDataB64Url = Base64
				.encodeBase64URLSafeString(encryptedData);
		String encryptionIvB64Url = Base64
				.encodeBase64URLSafeString(encryptionIv);

		StringBuilder sb = new StringBuilder(MAC_PREFIX);
		sb.append(DELIM).append(passwordId != null ? passwordId : "");
		sb.append(DELIM).append(encryptionSaltString);
		sb.append(DELIM).append(encryptionIvB64Url);
		sb.append(DELIM).append(encryptedDataB64Url);
		String hmacBaseString = sb.toString();

		/*
		 * Create integrity salt.
		 */

		String integritySaltString = generateSalt(integrityOptions.saltBits);
		byte[] integritySalt = integritySaltString
				.getBytes(StandardCharsets.UTF_8);

		/*
		 * Calculate HMAC.
		 */
		byte[] integrityHmac = hmac(charPassword, hmacBaseString,
				integritySalt, integrityOptions.algorithm,
				integrityOptions.iterations);

		String integrityHmacB64Url = Base64
				.encodeBase64URLSafeString(integrityHmac);

		StringBuilder sealedBuilder = new StringBuilder(hmacBaseString);
		sealedBuilder.append(DELIM).append(integritySaltString).append(DELIM)
				.append(integrityHmacB64Url);
		return sealedBuilder.toString();
	}

	/**
	 * Unseal an encapsulated token.
	 * 
	 * This method takes a token that has been encapsulated with seal() and
	 * returns the original sealed data.
	 * 
	 * @param encapsulatedToken
	 *            The encapsulated token
	 * 
	 * @param password
	 *            Symmetric password for sealing and unsealing the data.
	 * @param encryptionOptions
	 *            Parameters used for the encryption phase.
	 * @param integrityOptions
	 *            Parameters used for the integrity phase.
	 * @return The original data
	 * @throws JironIntegrityException
	 *             When the integrity of the token cannot be verified, this
	 *             exception is thrown. In this case, the token has been
	 *             corrupted (either by accident, e.g. truncation, or as part of
	 *             an attack).
	 * @throws JironException
	 */
	public static String unseal(String encapsulatedToken,String password,
			Options encryptionOptions, Options integrityOptions)
			throws JironException, JironIntegrityException {
		// Here we set the passwordMap to null
		return unseal(encapsulatedToken,null,password,encryptionOptions,integrityOptions);
	}
	
	/**
	 * Unseal an encapsulated token.
	 * 
	 * This method takes a token that has been encapsulated with seal() and
	 * returns the original sealed data.
	 * 
	 * @param encapsulatedToken
	 *            The encapsulated token
	 * 
	 * @param passwordMap
	 *            A map containing password IDs and passwords for lookup when doing password rotation.
	 * @param encryptionOptions
	 *            Parameters used for the encryption phase.
	 * @param integrityOptions
	 *            Parameters used for the integrity phase.
	 * @return The original data
	 * @throws JironIntegrityException
	 *             When the integrity of the token cannot be verified, this
	 *             exception is thrown. In this case, the token has been
	 *             corrupted (either by accident, e.g. truncation, or as part of
	 *             an attack).
	 * @throws JironException
	 */
	public static String unseal(String encapsulatedToken,Map<String,String> passwordMap,
			Options encryptionOptions, Options integrityOptions)
			throws JironException, JironIntegrityException {
		// Here we set the password to null
		return unseal(encapsulatedToken,passwordMap,null,encryptionOptions,integrityOptions);
	}
	
	
	private static String unseal(String encapsulatedToken, Map<String,String> passwordMap,String password,
			Options encryptionOptions, Options integrityOptions)
			throws JironException, JironIntegrityException {
		

		/*
		 * Split the token into parts.
		 */

		String[] parts = encapsulatedToken.split(DELIM_SPLIT_REGEX);
		if (parts.length != 7) {
			throw new JironIntegrityException(encapsulatedToken,
					"Unable to parse iron token, number of fields retrieved from split: "
							+ parts.length + ", token: " + encapsulatedToken);
		}

		String macPrefix = parts[0];
		String passwordId = parts[1];
		String encryptionSaltString = parts[2];
		String encryptionIvBase64Url = parts[3];
		String encryptedDataB64Url = parts[4];
		String integrityHmacSaltString = parts[5];
		String integrityHmacB64Url = parts[6];

		/*
		 * If there is no passwordId in the token, and thus
		 * no chance for password rotation, there must be
		 * a password supplied.
		 */
		if (passwordId.length() == 0) {
			if(password == null || password.length() == 0) {
				throw new JironException("Password is required for tokens that contain no password ID");
			}
		}
		
		/*
		 * If there is a passwordId in the token and if the caller
		 * has supplied a password lookup map, we try to lookup the 
		 * sealing password in there.
		 * If we find one, we set the original password parameter to
		 * this password.
		 */
		if (passwordId.length() > 0) {
			if(passwordMap != null) {
				String p = passwordMap.get(passwordId);
				if(p != null) {
					password = p;
				}
			}
		}
		
		/*
		 * If we do not have a password at this point, we cannot unseal.
		 */
		
		if (password == null && passwordId.length() == 0) {
			throw new JironException("Neither password provided nor password found in table");
		}
		
		/*
		 * Note:
		 * Above, we cover the case that a password has been supplied but that the ID has
		 * not been found. In this case, we try with the supplied password.
		 * FIXME: Maybe I'll change that later.
		 */
		
		/*
		 * Now we obtain a byte array from the password because that is
		 * what goes into the crypto functions.
		 */
		
		char[] charPassword = new char[password.length()];
		password.getChars(0, password.length(), charPassword, 0);
		

		/*
		 * Reconstruct HMAC base string for integrity verification.
		 */

		String hmacBaseString = macPrefix + DELIM + passwordId + DELIM
				+ encryptionSaltString + DELIM + encryptionIvBase64Url + DELIM
				+ encryptedDataB64Url;

		/*
		 * Integrity checks
		 */

		if (!macPrefix.equals(MAC_PREFIX)) {
			throw new JironIntegrityException(encapsulatedToken,
					"Sealed token uses prefix " + macPrefix
							+ " but this version of iron requires "
							+ MAC_PREFIX);
		}

		byte[] integrityByteSalt = integrityHmacSaltString
				.getBytes(StandardCharsets.UTF_8);
		byte[] checkIntegrityHmac = hmac(charPassword, hmacBaseString,
				integrityByteSalt, integrityOptions.algorithm,
				integrityOptions.iterations);
		String checkIntegrityHmacB64Url = Base64
				.encodeBase64URLSafeString(checkIntegrityHmac);

		/*
		 * Verify that received HMAC is the same as the one we recomputed abive.
		 */

		if (!fixedTimeEqual(checkIntegrityHmacB64Url, integrityHmacB64Url)) {
			// FIXME Does it make sense to put more information in message?
			throw new JironIntegrityException(encapsulatedToken, "Invalid HMAC");
		}

		/*
		 * Decrypt encapsulated data.
		 */

		byte[] encryptedData = Base64.decodeBase64(encryptedDataB64Url);
		byte[] encryptionIv = Base64.decodeBase64(encryptionIvBase64Url);
		byte[] encryptionSalt = encryptionSaltString
				.getBytes(StandardCharsets.UTF_8);

		SecretKey secretKey = generateKey(charPassword, encryptionSalt,
				encryptionOptions.algorithm, encryptionOptions.iterations);

		byte[] deencrypted = decrypt(encryptedData,
				encryptionOptions.algorithm, secretKey, encryptionIv);

		return new String(deencrypted, StandardCharsets.UTF_8);
	}

	/**
	 * Create an HMAC from a given password and baseString.
	 * 
	 * @param password
	 * @param baseString
	 * @param salt
	 * @param algorithm
	 * @param iterations
	 * @return The calculated HMAC.
	 * @throws JironException
	 */
	protected static byte[] hmac(char[] password, String baseString,
			byte[] salt, Algorithm algorithm, int iterations)
			throws JironException {

		SecretKey secretKey = generateKey(password, salt, algorithm, iterations);

		Mac mac;
		try {
			mac = Mac.getInstance(algorithm.transformation);
		} catch (NoSuchAlgorithmException e) {
			throw new JironException("Unknown algorithm "
					+ algorithm.transformation, e);
		}

		try {
			mac.init(secretKey);
		} catch (InvalidKeyException e) {
			throw new JironException("Key " + secretKey.toString()
					+ " is not valid", e);
		}
		return mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Encrypt some data.
	 * 
	 * @param data
	 * @param algorithm
	 * @param secretKey
	 * @param iv
	 * @return The encrypted data.
	 * @throws JironException
	 */
	protected static byte[] encrypt(byte[] data, Algorithm algorithm,
			SecretKey secretKey, byte[] iv) throws JironException {

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(algorithm.transformation);
		} catch (NoSuchAlgorithmException e) {
			throw new JironException("Encryption algorithm "
					+ algorithm.transformation + " not found", e);
		} catch (NoSuchPaddingException e) {
			throw new JironException("Cannot work with padding given by "
					+ algorithm.transformation, e);
		}

		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			throw new JironException("Key " + secretKey.toString()
					+ " is invalid", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new JironException(
					"Initialization vector passed to cipher initialization", e);
		}

		try {
			return cipher.doFinal(data); // encrypted;
		} catch (IllegalBlockSizeException e) {
			throw new JironException("Illegal block size when decrypting", e);
		} catch (BadPaddingException e) {
			throw new JironException("Bad padding when decrypting", e);
		}
	}

	/**
	 * Decrypt some encrypted data.
	 * 
	 * @param encryptedData
	 * @param algorithm
	 * @param secretKey
	 * @param iv
	 * @return The decrypted data.
	 * @throws JironException
	 */
	protected static byte[] decrypt(byte[] encryptedData, Algorithm algorithm,
			SecretKey secretKey, byte[] iv) throws JironException {

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(algorithm.transformation);
		} catch (NoSuchAlgorithmException e) {
			throw new JironException("Encryption algorithm "
					+ algorithm.transformation + " not found", e);
		} catch (NoSuchPaddingException e) {
			throw new JironException("Cannot work with padding given by "
					+ algorithm.transformation, e);
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			throw new JironException("Key " + secretKey.toString()
					+ " is invalid", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new JironException(
					"Initialization vector passed to cipher initialization seems to be invalid algorithm parameter",
					e);
		}

		try {
			return cipher.doFinal(encryptedData);
		} catch (IllegalBlockSizeException e) {
			throw new JironException("Illegal block size when decrypting", e);
		} catch (BadPaddingException e) {
			throw new JironException("Bad padding when decrypting", e);
		}
	}

	/**
	 * Generates a secret key from the given password and salt.
	 * <p>
	 * Key size will be determined from the passed algorithm.
	 * </p>
	 * 
	 * @param password
	 * @param salt
	 * @param algorithm
	 * @param iterations
	 * @return The generated key.
	 * @throws JironException
	 */
	protected static SecretKey generateKey(char[] password, byte[] salt,
			Algorithm algorithm, int iterations) throws JironException {

		SecretKeyFactory keyFactory;
		try {
			keyFactory = SecretKeyFactory.getInstance(KEYGEN_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new JironException("Algorithm " + KEYGEN_ALGORITHM
					+ " not found by SecretKeyFactory", e);
		}
		KeySpec keySpec = new PBEKeySpec(password, salt, iterations,
				algorithm.keyBits);

		try {
			// See ISSEUS.txt for the two lines
			SecretKey key = keyFactory.generateSecret(keySpec);
			// For "AES" see ISSUES.txt
			return new SecretKeySpec(key.getEncoded(), "AES");
		} catch (InvalidKeySpecException e) {
			throw new JironException(
					"KeySpec is invalid " + keySpec.toString(), e);
		}
	}

	/**
	 * Generate an initialization vector.
	 * 
	 * <p>
	 * Unlike generateSalt() this method returns a byte array, that needs to be
	 * further encoded (e.g. Base64Url) to be suitable for URLs or HTTP headers.
	 * </p>
	 * 
	 * @param nbits
	 *            The size of the vector in bits. The initialization vector will
	 *            be given a size of ceil(nbits/8) bytes.
	 * @return The initialization vector.
	 */
	protected static byte[] generateIv(int nbits) {
		int nbytes = (int) Math.ceil((double) nbits / 8d);
		byte[] iv = new byte[nbytes];
		Random r = new SecureRandom();
		r.nextBytes(iv);
		return iv;
	}

	/**
	 * Generates a random salt and returns as a String. With each salt byte
	 * being represented in the string as a hex value in two chars.
	 * 
	 * <p>
	 * The salt can be inserted as-is into the iron token string.
	 * </p>
	 * <p>
	 * The random generator used internally is java.crypto.SecureRandom.
	 * </p>
	 * 
	 * @param nbits
	 *            Size of the salt in bits. The salt will be given a size of
	 *            ceil(nbits/8) * 2 bytes
	 * @return The salt in hex-encoded form, suitable for URLs or HTTP headers.
	 */
	protected static String generateSalt(int nbits) {
		int nbytes = (int) Math.ceil((double) nbits / 8d);
		byte[] salt = new byte[nbytes];
		Random r = new SecureRandom();
		r.nextBytes(salt);
		return bytesToHex(salt);
	}

	/**
	 * Convert a byte array to a string using. This method turns a byte array
	 * into a string using two characters per byte and encoding the byte value
	 * as a two character hex value.
	 * <p>
	 * The resulting string will have a length twice as long as the original
	 * byte array.
	 * </p>
	 * <p>
	 * The string will be suitable for use in URLs or HTTP headers etc. without
	 * further escaping.
	 * </p>
	 * 
	 * 
	 * @param bytes
	 *            The byte array to turn into a string.
	 * @return Byes of the array as a string.
	 */
	protected static String bytesToHex(byte[] bytes) {
		final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for (int j = 0; j < bytes.length; j++) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	/**
	 * Fixed time comparison of two strings.
	 * 
	 * Fixed time comparison is necessary in order to prevent attacks analyzing
	 * differences in verification time for corrupted tokens.
	 * 
	 * @param lhs
	 *            Left hand side operand
	 * @param rhs
	 *            Right hadn side operand
	 * @return true if the strings are equal, false otherwise.
	 */
	protected static boolean fixedTimeEqual(String lhs, String rhs) {

		boolean equal = (lhs.length() == rhs.length() ? true : false);

		// If not equal, work on a single operand to have same length.
		if (!equal) {
			rhs = lhs;
		}
		int len = lhs.length();
		for (int i = 0; i < len; i++) {
			if (lhs.charAt(i) == rhs.charAt(i)) {
				equal = equal && true;
			} else {
				equal = equal && false;
			}
		}

		return equal;
	}

}
