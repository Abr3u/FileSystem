package domain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.Charset;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import exceptions.CantVerifySignatureException;

public class Impl extends UnicastRemoteObject implements BlockServerInterface {

	
	private static final int HASHSIZE=32;
	private static final String ARRAY_FILE_NAME = "filesArray.ser";
	private ArrayList<BSFile> _files = new ArrayList<BSFile>();
	private boolean debugMode;

	public Impl(int port,boolean debug) throws RemoteException, IllegalArgumentException {
		super(port);
		debugMode=debug;
		File f = new File(ARRAY_FILE_NAME);
		if(f.exists()) {
			readFilesFromSystem();
		}	
	}
	
	private void writeFilesToSystem(){
		try
        {
               FileOutputStream fos =
                  new FileOutputStream(ARRAY_FILE_NAME);
               ObjectOutputStream oos = new ObjectOutputStream(fos);
               oos.writeObject(_files);
               oos.close();
               fos.close();
        }catch(IOException ioe)
         {
               ioe.printStackTrace();
         }
	}
	
	private void readFilesFromSystem() {
		ArrayList<BSFile> array = null;
	      try
	      {
	         FileInputStream fis = new FileInputStream(ARRAY_FILE_NAME);
	         ObjectInputStream ois = new ObjectInputStream(fis);
	         array = (ArrayList) ois.readObject();
	         ois.close();
	         fis.close();
	      }catch(IOException ioe)
	      {
	         ioe.printStackTrace();
	      }catch(ClassNotFoundException c)
	      {
	         System.out.println("Class not found");
	         c.printStackTrace();
	      }	
	      _files = new ArrayList<BSFile>();
	      _files.addAll(array);
	    }

	@Override
	public byte[] get(byte[] id) throws RemoteException{
		System.out.println("get @ BlackServer");
		for(BSFile file: _files){
			if(file.containsBlock(id)){
				if(debugMode  && !file.getBlock(id).getClass().getName().contains("PK")){
					byte[] corrupted = {(byte) 7};
					return corrupted;
				}
				else{
					if(file.getBlock(id) instanceof domain.PKBlock){
						PKBlock pk = (PKBlock) file.getBlock(id);
						byte[] returnContent = new byte[pk.getSignature().length + pk.getContent().length];
						System.arraycopy(pk.getSignature(), 0, returnContent, 0, pk.getSignature().length);
						System.arraycopy(pk.getContent(), 0, returnContent, pk.getSignature().length, pk.getContent().length);
						System.out.println(pk.getSignature().length);
						return returnContent;
					}else{
						return (file.getBlock(id)).getContent();
					}
				}
			}
		}
		return null;
	}
	
	private static byte[] toDecodedBase64ByteArray(byte[] base64EncodedByteArray){ 
		return DatatypeConverter.parseBase64Binary(new String(base64EncodedByteArray, Charset.forName("UTF-8"))); 
	}
	
	@Override
	public byte[] put_k(byte[] data, byte[] signature, java.security.PublicKey public_key/*, byte[] recover, int pos, int size*/)
	throws CantVerifySignatureException{
		System.out.println("put_k @ BlackServer");
		BSFile file = null;
		if (!checkSignature(data, signature, public_key)) {
			throw new CantVerifySignatureException();
		}
		byte[] id = getHash(Base64.getEncoder().encodeToString(public_key.getEncoded()).getBytes());
		for(BSFile f: _files){
			if(f.containsBlock(id))
			{
				file = f;
			}
		}
		PKBlock pkBlock = new PKBlock(id,data,signature);
		if(file!=null){
			file.addBlock(pkBlock);
			System.out.println("Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
		}else{
			System.out.println("Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
			file = new BSFile();
			file.addBlock(pkBlock);
			_files.add(file);
		}
		writeFilesToSystem();
		return id;
	}
	
	
	public byte[] getHash(byte[] data){
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
			md.update(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		byte[] digest = md.digest();
		return digest;
	}
	
	public byte[] put_h(byte[] content){
		System.out.println("put_h @ BlackServer");
		byte[] file_id = Arrays.copyOfRange(content,0,HASHSIZE);
		byte[] file_content = Arrays.copyOfRange(content, HASHSIZE, content.length);
		byte[] id = getHash(file_content);
		ContentBlock block = new ContentBlock(id,file_content);
		for(BSFile file: _files){
			if(file.containsBlock(file_id)){
				file.addBlock(block);
				System.out.println("Adicionei HBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + file_content.length);
			}
		}
		return id;
	}
	
	private boolean checkSignature(byte[] data, byte[] signature, java.security.PublicKey public_key) {
		byte[] digest = getHash(data);
		
		byte[] decrypted = decrypt(signature, public_key);
		
		if(Arrays.equals(digest,decrypted)){
			return true;
		}
		return false;
	}
	
	private byte[] decrypt(byte[] buffer, java.security.PublicKey key) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.DECRYPT_MODE, key);
			return rsa.doFinal(buffer);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}