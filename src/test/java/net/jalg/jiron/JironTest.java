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

	@Test
	public void testSealUnseal() {
		try {
			String sealed = Jiron.seal(data, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			String unsealed = Jiron.unseal(sealed, pwd,
					Jiron.DEFAULT_ENCRYPTION_OPTIONS,
					Jiron.DEFAULT_INTEGRITY_OPTIONS);
			assertEquals(data,unsealed);
		} catch (JironException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		} catch (JironIntegrityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fail("Fail" + e.getMessage());
		}

	}

}
