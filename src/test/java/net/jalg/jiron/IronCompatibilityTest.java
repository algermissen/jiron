package net.jalg.jiron;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * This test is a compatibility test with iron.
 * 
 * It takes one of the test tokens from the <a
 * href="https://github.com/hueniverse/iron/blob/master/test/index.js">iron
 * tests</a> and unseals them with the Java implementation. This is done to
 * ensure that the encryption and integrity verification procedure has been
 * implemented in the right way and that encoding issues of byte/string
 * conversions are handled the same way in both libraries.
 * 
 */
public class IronCompatibilityTest {

	@Test
	public void testUnseal() throws JironException, JironIntegrityException {

		// Test data adapted from
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String ironTestData = "{\"a\":1,\"b\":2,\"c\":[3,4,5],\"d\":{\"e\":\"f\"}}";

		// Test token from
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String token = "Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw";

		// Test token from
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String pwd = "some_not_random_password";

		String unsealed = Jiron.unseal(token, pwd,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		assertEquals(ironTestData, unsealed);
		
		
		String x = "This is a message";
		String s = Jiron.seal(x, "password", Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		
		String t = "Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw";
		String z1 = "Fe26.1**646fcab29f11d40aafb61a8ad7fa07488ff5f58b30acc7ac63744e3d561fb2cc*tAOjySWtIoeKkGvecTdCHQ*VX2rNBZzzRARRRrFPkWX1_Fa_X-2C6zUIAGN20dyr84*45bcc0ecfd186ca02891df449ab908f631452dd0dfe3f73a24bdb0344444bc6a*2gmP4mEbbygJzeQ_xi7KpFUt77lWvc8kF1TKSyWbQHQ";
		String z = "Fe26.1**0ccf345e9467351fc3732fc3be087cc454bbee1a6efb7f91d34edd2e8047214e*bDLL_LyjUzQDPO08g_btYQ*rIrkMFcYNhiIebiItxxaVzcLFg2d-jjWOXiLS4rB26sVeFAsAw3It0p_xfRDjEju*8e8a67083d8211387e89ff5ae3cc4424c57df74776c7f17968bd4067d6ca6462*FV5Jxh7HeoWs3NR2uh2I5prm8h_771U1DOYzRAgudVY";
		
		
		
		unsealed = Jiron.unseal(z, "xxx",
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
		
		

	}

}
