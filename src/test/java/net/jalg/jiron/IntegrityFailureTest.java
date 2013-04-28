package net.jalg.jiron;


import org.junit.Test;

public class IntegrityFailureTest {

	private String pwd = "secret";

	@Test(expected = JironIntegrityException.class)
	public void testPrefixMismatch() throws JironException,
			JironIntegrityException {
		String badPrefixToken = "xFe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";
		Jiron.unseal(badPrefixToken, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}

	@Test(expected = JironIntegrityException.class)
	public void testWrongTokenSyntax() throws JironException,
			JironIntegrityException {
		String eightFieldsToken = "x*Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";
		Jiron.unseal(eightFieldsToken, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}

	@Test(expected = JironIntegrityException.class)
	public void testHmacMismatch() throws JironException,
			JironIntegrityException {
		String badHmacToken = "Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*xodsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";
		Jiron.unseal(badHmacToken, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}
	
	@Test(expected = JironIntegrityException.class)
	public void testCorruptEncryptedMismatch() throws JironException,
			JironIntegrityException {
		String badToken = "Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*xAFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";
		Jiron.unseal(badToken, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}
	
	@Test(expected = JironIntegrityException.class)
	public void testWrongIntegritySalt() throws JironException,
			JironIntegrityException {
		String badToken = "Fe26.1**FFCC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";
		Jiron.unseal(badToken, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);
	}

}
