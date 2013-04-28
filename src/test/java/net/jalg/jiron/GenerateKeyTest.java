package net.jalg.jiron;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.jalg.jiron.Jiron.Algorithm;
import net.jalg.jiron.Jiron.Options;
import net.jalg.jiron.util.Base64;

import org.junit.Test;


public class GenerateKeyTest {
	
	private char[] pwd = { 's','e','c','r','e','t'};

	@Test
	public void testGenerateKey() {
		
		Options opt = Jiron.DEFAULT_ENCRYPTION_OPTIONS;
		int nbytes = (int) Math.ceil(opt.algorithm.keyBits/8d);

		String saltString = Jiron.generateSalt(opt.saltBits);
		byte[] salt = saltString.getBytes(StandardCharsets.UTF_8);
		

		try {
			System.out.println("SALT: " + saltString);
			System.out.println("SALT: " + salt);
			SecretKey key1 = Jiron.generateKey(pwd, salt,opt.algorithm,opt.iterations);
			System.out.println("SALT: " + saltString);
			System.out.println("SALT: " + salt);
			
			SecretKey key2 = Jiron.generateKey(pwd, salt,opt.algorithm,opt.iterations);
			System.out.println("SALT: " + saltString);
			System.out.println("SALT: " + salt);
			
//			System.out.println("K1: " + Base64.encode(key1.getEncoded()));
//			System.out.println("K2: " + Base64.encode(key2.getEncoded()));
			
			assertTrue(key1.equals(key2));
			assertTrue(key2.equals(key1));
			
			assertEquals(nbytes,key1.getEncoded().length);
			assertEquals(nbytes,key2.getEncoded().length);
			
		} catch (JironException e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		
		
	}
	
	

}
