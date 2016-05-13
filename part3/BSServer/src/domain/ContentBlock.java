package domain;

public class ContentBlock extends Block {

	public ContentBlock(byte[] id,byte[] content, int wts){
		_id = id;
		_content = content;
		_wts = wts;
	}
}
