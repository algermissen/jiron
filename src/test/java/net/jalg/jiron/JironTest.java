package net.jalg.jiron;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.jalg.jiron.Jiron.Algorithm;
import net.jalg.jiron.Jiron.Options;

import org.junit.Test;


public class JironTest {

	private String pwd = "secret";
	private String data = "this is a secret message";
	
	private String token = "Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";

	@Test
	public void testSealUnseal() {
		try {
			String sealed = Jiron.seal(data, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			
			System.out.println("_" + sealed + "_");
			
			String unsealed = Jiron.unseal(sealed, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			
			assertEquals(data,unsealed);
			
		} catch (JironException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		} catch (JironIntegrityException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		}

	}
	
	@Test
	public void testUnseal() {
		try {
			String unsealed = Jiron.unseal(token, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			
			assertEquals(data,unsealed);
			
		} catch (JironException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		} catch (JironIntegrityException e) {
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		}

	}
	
	//Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw
	
	

}
