package domain;

import java.io.Serializable;

public abstract class Block implements Serializable{
	protected byte[] _content;
	protected byte[] _id;
	
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
