package net.jalg.jiron;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import net.jalg.jiron.Jiron.Options;

import org.junit.Test;


public class HmacTest {
	
	private char[] pwd = { 's','e','c','r','e','t'};
	private String data = "this is a secret message";

	@Test
	public void testHmac() throws JironException {
		Options opt = Jiron.DEFAULT_INTEGRITY_OPTIONS;
		
		String integritySalt = Jiron.generateSalt(opt.saltBits);
		byte[] integrityByteSalt = integritySalt.getBytes(StandardCharsets.UTF_8);

			byte[] mac = Jiron.hmac(pwd, data, integrityByteSalt, opt.algorithm, opt.iterations);
		
	}

}
