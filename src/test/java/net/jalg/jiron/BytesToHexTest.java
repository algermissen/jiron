package net.jalg.jiron;

import static org.junit.Assert.*;

import net.jalg.jiron.util.Base64;

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
		byte c[] = { 62,1, 2, 3, 4, 5, 6 ,7 , 120, 60, 61,63,65, 44, 21,22,23,24,30,31,32,45, 92,93,94,95, 80,81,82,83,84};
		System.out.println("[" +Base64.encodeBase64URLSafeString(c)+"]");
		
		byte d[] = {(byte)0xcf,(byte)0xb3,(byte)0xe2,(byte)0xe3,(byte)0xcc,(byte)0x7f,(byte)0xae,(byte)0xfd,(byte)0x55,(byte)0x4a,(byte)0x38,(byte)0x59,(byte)0x52,(byte)0x7d,(byte)0xca,(byte)0x5b};
		System.out.println("[" +Base64.encodeBase64URLSafeString(d)+"]");
		// [z7Pi48x_rv1VSjhZUn3KWw]
		
		byte e[] = {(byte)0xa9,(byte)0x6d,(byte)0x20,(byte)0x77,(byte)0x5f,(byte)0xa9,(byte)0xe2,(byte)0xb9,(byte)0xb2,(byte)0x92,(byte)0x92,(byte)0x07,(byte)0xa0,(byte)0xa0,(byte)0x36,(byte)0x25,(byte)0x4d,(byte)0xff,(byte)0x29,(byte)0x9d,(byte)0xb9,(byte)0x33,(byte)0x09,(byte)0xd7,(byte)0xb1,(byte)0x2b,(byte)0x16,(byte)0x9f,(byte)0x5d,(byte)0xcb,(byte)0x04,(byte)0x16};
		
		System.out.println("[" +Base64.encodeBase64URLSafeString(e)+"]");
		//[qW0gd1-p4rmykpIHoKA2JU3_KZ25MwnXsSsWn13LBBY]
				
				
		
		
	}
	
	

}
