package net.jalg.jiron;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class JironTest {

	private String pwd = "secret";
	private String data = "this is a secret message";

	private String token = "Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";

	@Test
	public void testSealUnseal() throws JironException, JironIntegrityException {
		String sealed = Jiron.seal(data, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		// .out.println("_" + sealed + "_");

		String unsealed = Jiron.unseal(sealed, pwd,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		assertEquals(data, unsealed);
	}

	@Test
	public void testUnseal() throws JironException, JironIntegrityException {
		String unsealed = Jiron.unseal(token, pwd,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		assertEquals(data, unsealed);

	}
	
	@Test
	public void testSealUnsealPwdRotation() throws JironException, JironIntegrityException {

		Map<String,String> pwdMap = new HashMap<String,String>();
		pwdMap.put("1", "test");
		pwdMap.put("2", pwd);
		pwdMap.put("3", "foo");
		
		String sealed = Jiron.seal(data, "2", pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		String unsealed = Jiron.unseal(sealed, pwdMap,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		assertEquals(data, unsealed);
	}
	
	@Test
	public void testUnsealPwdRotation() throws JironException, JironIntegrityException {
		
		String token2 = "Fe26.1*3*81a234d22d0e5108b809b93ce6036725b3be09dd0752206e9a28db18b812695e*5QsokuciDSmIYFDruIg2hA*-eNOlZJ5HwAp5cKX-AY-xA*466db367ac2ee4d9666665266a0b9f3f863ee5fde68a690a3e09f510b1f7623e*yxd_WGJyES4TSVZCEZjGAhxnIkmaPtTO8MkQxIm9Y3U";

		Map<String,String> pwdMap = new HashMap<String,String>();
		pwdMap.put("1", "test");
		pwdMap.put("2", pwd);
		pwdMap.put("3", "foo");
		

		String unsealed = Jiron.unseal(token2, pwdMap,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		assertEquals("This is secret", unsealed);
	}
	
	@Test(expected = JironException.class)
	public void testUnsealPwdRotationFailsPwdNotFound() throws JironException, JironIntegrityException {
		
		String token = "Fe26.1*3*81a234d22d0e5108b809b93ce6036725b3be09dd0752206e9a28db18b812695e*5QsokuciDSmIYFDruIg2hA*-eNOlZJ5HwAp5cKX-AY-xA*466db367ac2ee4d9666665266a0b9f3f863ee5fde68a690a3e09f510b1f7623e*yxd_WGJyES4TSVZCEZjGAhxnIkmaPtTO8MkQxIm9Y3U";

		Map<String,String> pwdMap = new HashMap<String,String>();
		pwdMap.put("1", "test");
		pwdMap.put("2", pwd);

		String unsealed = Jiron.unseal(token, pwdMap,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}
	
	@Test(expected = JironIntegrityException.class)
	public void testUnsealPwdRotationFailsWrongPwd() throws JironException, JironIntegrityException {
		
		String token = "Fe26.1*3*81a234d22d0e5108b809b93ce6036725b3be09dd0752206e9a28db18b812695e*5QsokuciDSmIYFDruIg2hA*-eNOlZJ5HwAp5cKX-AY-xA*466db367ac2ee4d9666665266a0b9f3f863ee5fde68a690a3e09f510b1f7623e*yxd_WGJyES4TSVZCEZjGAhxnIkmaPtTO8MkQxIm9Y3U";

		Map<String,String> pwdMap = new HashMap<String,String>();
		pwdMap.put("1", "test");
		pwdMap.put("2", pwd);
		pwdMap.put("3", "lkehfklwehflkh");

		String unsealed = Jiron.unseal(token, pwdMap,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}
	
	@Test(expected = JironException.class)
	public void testRotationUnsealFailsIfNoIdInToken() throws JironException, JironIntegrityException {
		

		Map<String,String> pwdMap = new HashMap<String,String>();
		pwdMap.put("1", "test");
		pwdMap.put("2", pwd);
		pwdMap.put("3", "foo");
		
		String sealed = Jiron.seal(data, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		String unsealed = Jiron.unseal(sealed, pwdMap,
				Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}

}
