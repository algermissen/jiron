package net.jalg.jiron;

public class JironIntegrityException extends Exception {

	private String token;

	public JironIntegrityException(String token,String message, Throwable cause) {
		super(message, cause);
		this.token = token;
	}

	public JironIntegrityException(String token,String message) {
		super(message);
		this.token = token;
	}

	public JironIntegrityException(String token,Throwable cause) {
		super(cause);
		this.token = token;
	}

	public String getToken() {
		return token;
	}
	
	

}
