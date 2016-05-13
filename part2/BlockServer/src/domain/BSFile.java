package domain;


import java.io.Serializable;
import java.util.Arrays;
import java.util.ArrayList;

public class BSFile implements Serializable{
	
	private ArrayList<Block> _blocks;

	public BSFile() {
		_blocks = new ArrayList<Block>();
	}
	
	public void addBlock(Block block){
		ArrayList<Block> aux = new ArrayList<Block>(_blocks);
		for(Block b: aux){
			if(Arrays.equals(b.getId(), block.getId()))
			{
				_blocks.remove(b);
			}
		}
		_blocks.add(block);
	}
	
	public boolean containsBlock(byte[] id){
		for(Block b: _blocks){
			//System.out.println("Found block \n"+Arrays.toString(b.getId()));
			if(Arrays.equals(b.getId(),id)){
				//System.out.println("@contains found block");
				return true;
			}
		}
		//System.out.println("@contains didnt find block \n"+Arrays.toString(id));
		return false;
	}
	
	public Block getBlock(byte[] id){
		for(Block b: _blocks){
			if(Arrays.equals(b.getId(),id)){
				System.out.println("Found block in getBlock!");
				return b;
			}
		}
		return null;
	}
}
