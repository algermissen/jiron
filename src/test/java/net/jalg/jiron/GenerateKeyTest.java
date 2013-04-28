package net.jalg.jiron;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import net.jalg.jiron.Jiron.Options;

import org.junit.Test;

public class GenerateKeyTest {

	private char[] pwd = { 's', 'e', 'c', 'r', 'e', 't' };

	@Test
	public void testGenerateKey() throws JironException {

		Options opt = Jiron.DEFAULT_ENCRYPTION_OPTIONS;
		int nbytes = (int) Math.ceil(opt.algorithm.keyBits / 8d);

		String saltString = Jiron.generateSalt(opt.saltBits);
		byte[] salt = saltString.getBytes(StandardCharsets.UTF_8);

			SecretKey key1 = Jiron.generateKey(pwd, salt, opt.algorithm,
					opt.iterations);
			SecretKey key2 = Jiron.generateKey(pwd, salt, opt.algorithm,
					opt.iterations);

			assertTrue(key1.equals(key2));
			assertTrue(key2.equals(key1));
			assertEquals(nbytes, key1.getEncoded().length);
			assertEquals(nbytes, key2.getEncoded().length);

	}

}
