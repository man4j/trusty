package ru.ussgroup.security.trusty.exception;

public class TrustyOCSPUnknownProblemException extends Exception {
	public TrustyOCSPUnknownProblemException() {
		super();
	}

	public TrustyOCSPUnknownProblemException(String message, Throwable cause) {
		super(message, cause);
	}

	public TrustyOCSPUnknownProblemException(String message) {
		super(message);
	}

	public TrustyOCSPUnknownProblemException(Throwable cause) {
		super(cause);
	}
}
