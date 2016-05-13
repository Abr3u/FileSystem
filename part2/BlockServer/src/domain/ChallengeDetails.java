package domain;

import java.util.Date;

public class ChallengeDetails {

	private Date validUntil;
	private byte[] expected;
	
	public ChallengeDetails(Date d, byte[] e) {
		this.validUntil=d;
		this.expected=e;
	}
	
	
	public Date getValidUntil() {
		return validUntil;
	}

	public void setValidUntil(Date validUntil) {
		this.validUntil = validUntil;
	}

	public byte[] getExpected() {
		return expected;
	}

	public void setExpected(byte[] expected) {
		this.expected = expected;
	}
	
}
