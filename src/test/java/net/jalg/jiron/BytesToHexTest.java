package net.jalg.jiron;

import static org.junit.Assert.*;

import org.junit.Test;

public class BytesToHexTest {

	@Test
	public void testBytesToHex() {
		byte[] b = { 1 , 2 , 10};
		String s = Jiron.bytesToHex(b);
		assertEquals("01020A",s);
	}
	
	@Test
	public void testBytesToHexEmpty() {
		byte[] b = { };
		String s = Jiron.bytesToHex(b);
		assertEquals("",s);
	}
	
	@Test
	public void testBytesToHex00() {
		byte[] b = {0 };
		String s = Jiron.bytesToHex(b);
		assertEquals("00",s);
	}
	@Test
	public void testBytesToHex0000() {
		byte[] b = {0 , 0};
		String s = Jiron.bytesToHex(b);
		assertEquals("0000",s);
	}

}
