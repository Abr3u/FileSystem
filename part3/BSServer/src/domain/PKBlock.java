package domain;

public class PKBlock extends Block{

	private byte[] _signature;
	private double _bytesWritten;
	public PKBlock(byte[] id, byte[] content,byte[] signature, int wts){
		_id = id;
		_content = content;
		_signature = signature;
		_wts=wts;
	}
	
	public byte[] getSignature(){
		return _signature;
	}
	
	public void setSignature(byte[] signature){
		_signature = signature;
	}
}
