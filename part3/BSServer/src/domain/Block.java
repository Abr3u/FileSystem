package domain;

import java.io.Serializable;

public abstract class Block implements Serializable{
	protected byte[] _content;
	protected byte[] _id;
	protected int _wts;
	
	public int get_wts() {
		return _wts;
	}

	public void set_wts(int _wts) {
		this._wts = _wts;
	}

	public void setContent(byte[] content){
		_content = content;
	}
	
	public byte[] getId(){
		return _id;
	}
	
	public void setId(byte[] id){
		_id = id;
	}
	
	public byte[] getContent(){
		return _content;
	}
}
