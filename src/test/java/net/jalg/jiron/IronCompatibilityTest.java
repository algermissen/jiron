package net.jalg.jiron;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.jalg.jiron.Jiron.Algorithm;
import net.jalg.jiron.Jiron.Options;

import org.junit.Test;


/**
 * This test is a compatibility test with iron.
 */
public class IronCompatibilityTest {

	@Test
	public void testUnseal() {
		
		// Test data adapted from 
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String ironTestData = "{\"a\":1,\"b\":2,\"c\":[3,4,5],\"d\":{\"e\":\"f\"}}";

		// Test token from
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String token = "Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw";
		
		// Test token from
		// https://github.com/hueniverse/iron/blob/master/test/index.js
		String pwd = "some_not_random_password";
		
		try {
			String unsealed = Jiron.unseal(token, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			
			assertEquals(ironTestData,unsealed);
			
		} catch (JironException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		} catch (JironIntegrityException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		}

	}
	
	
	

}
