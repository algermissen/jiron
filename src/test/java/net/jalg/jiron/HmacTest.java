package net.jalg.jiron;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.jalg.jiron.Jiron.Algorithm;
import net.jalg.jiron.Jiron.Options;

import org.junit.Test;


public class HmacTest {
	
	private char[] pwd = { 's','e','c','r','e','t'};
	private String data = "this is a secret message";

	@Test
	public void testHmac() {
		Options opt = Jiron.DEFAULT_INTEGRITY_OPTIONS;
		
		String integritySalt = Jiron.generateSalt(opt.saltBits);
		byte[] integrityByteSalt = integritySalt.getBytes(StandardCharsets.UTF_8);

		try {
			byte[] mac = Jiron.hmac(pwd, data, integrityByteSalt, opt.algorithm, opt.iterations);
			System.out.println("mac: " + new String(mac));
		} catch (JironException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fail("Exc:" + e.getMessage());
		}
		

		
		
		
	}
	
	

}
