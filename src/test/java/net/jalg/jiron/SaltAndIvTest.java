package net.jalg.jiron;

import static org.junit.Assert.*;

import org.junit.Test;

public class SaltAndIvTest {

	@Test
	public void testGenerateSalt() {
		
		String s = Jiron.generateSalt(8);
		assertEquals(2,s.length());
		
		s = Jiron.generateSalt(7);
		assertEquals(2,s.length());
		
		s = Jiron.generateSalt(14);
		assertEquals(4,s.length());
		
		s = Jiron.generateSalt(0);
		assertEquals(0,s.length());
		
		s = Jiron.generateSalt(-4);
		assertEquals(0,s.length());
		
		
	}
	
	@Test
	public void testGenerateIv() {
		
		byte[] iv = Jiron.generateIv(8);
		assertEquals(1,iv.length);
		
		iv = Jiron.generateIv(3);
		assertEquals(1,iv.length);
		
		iv = Jiron.generateIv(16);
		assertEquals(2,iv.length);
		
	}
	

}
