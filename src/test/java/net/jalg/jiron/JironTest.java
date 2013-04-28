package net.jalg.jiron;

import static org.junit.Assert.*;

import org.junit.Test;

public class JironTest {

	private String pwd = "secret";
	private String data = "this is a secret message";

	private String token = "Fe26.1**CC5008859A2A63A046D8240AE30880C9A12912AA3C3CB7F17BB3F907E8DCE9FD*AFRdKCjV21oEv_heVJCMbQ*cRg8DsGD0c3cNt4KN4zhShKLrJTRYOWsZz-xN7IuIZE*7D74165943A96694F8AC159FF5A1A4DBE7B6E180E6E913E2C16831FB425B03E4*odsqz5NMOwLYHRunRo1WM18QFgYOlWg7k9onmSyd5_Q";

	@Test
	public void testSealUnseal() throws JironException, JironIntegrityException {
		String sealed = Jiron.seal(data, pwd, Jiron.DEFAULT_ENCRYPTION_OPTIONS,
				Jiron.DEFAULT_INTEGRITY_OPTIONS);

		// System.out.println("_" + sealed + "_");

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

}
