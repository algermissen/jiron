package net.jalg.jiron;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.jalg.jiron.Jiron.Algorithm;
import net.jalg.jiron.Jiron.Options;

import org.junit.Test;


public class EncryptionTest {
	
	private char[] pwd = { 's','e','c','r','e','t'};
	private String data = "this is a secret message";
	
	@Test
	public void testGenerateKey() {
		Options opt = Jiron.DEFAULT_ENCRYPTION_OPTIONS;
		String saltString = Jiron.generateSalt(opt.saltBits);
		byte[] salt = saltString.getBytes(StandardCharsets.UTF_8);

		try {
			SecretKey key1 = Jiron.generateKey(pwd, salt,opt.algorithm,opt.iterations);
			byte[] iv = Jiron.generateIv(opt.algorithm.ivBits);
			
			byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
			byte[] enc = Jiron.encrypt(bytes, opt.algorithm, key1, iv);
			
			SecretKey key2 = Jiron.generateKey(pwd, salt,opt.algorithm,opt.iterations);
			byte[] dec = Jiron.decrypt(enc, opt.algorithm, key2, iv);
			String decMsg = new String(dec , StandardCharsets.UTF_8);

			assertEquals(decMsg,data);
			
			
		} catch (JironException e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		
		
	}
	
	


//	@Test
//	public void testGenerateKey() {
//		
//		
//		Options opt = Jiron.DEFAULT_ENCRYPTION_OPTIONS;
//		int nbytes = (int) Math.ceil(opt.algorithm.getKeyBits()/8d);
//
//		String saltString = Jiron.generateSalt(opt.saltBits);
//		byte[] salt = saltString.getBytes(StandardCharsets.UTF_8);
//		
//		
//
//		try {
//			
//			System.out.println("SALT: " + saltString);
//			System.out.println("SALT: " + salt);
//			SecretKey key1 = Jiron.generateKey(pwd, salt,opt.algorithm,opt.iterations);
//			
//			byte[] iv = Jiron.generateIv(opt.algorithm.getIvBits());
//			
//			byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
//			
//			byte[] enc = Jiron.encrypt(bytes, opt.algorithm, key1, iv);
//				
//			System.out.println("xxxxxx");
//			
//			byte[] dec = Jiron.decrypt(enc, opt.algorithm, key1, iv);
//			
//			String decMsg = new String(dec , StandardCharsets.UTF_8);
//			
//			System.out.println(".... " + decMsg);
//			
//			
//			
//		} catch (JironException e) {
//			e.printStackTrace();
//			fail(e.getMessage());
//		}
//		
//		
//	}
	
	

}
