package ru.ussgroup.security.trusty.exception;

public class TrustyOCSPNotAvailableException extends Exception {
	public TrustyOCSPNotAvailableException() {
		super();
	}

	public TrustyOCSPNotAvailableException(String message, Throwable cause) {
		super(message, cause);
	}

	public TrustyOCSPNotAvailableException(String message) {
		super(message);
	}

	public TrustyOCSPNotAvailableException(Throwable cause) {
		super(cause);
	}
}
