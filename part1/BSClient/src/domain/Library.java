package domain;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import com.sun.corba.se.spi.orbutil.fsm.Guard.Result;
import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader.Array;

import exceptions.BufferTooShortException;
import exceptions.CantFindFileException;
import exceptions.CantVerifyContentException;
import exceptions.CantVerifySignatureException;

public class Library {

	private static final int SERVER_PORT = 8888;
	private static final String SERVICE = "BlockServerService";
	private static final int SIZE = 2048;
	private static final String CERTIFICATE_NAME = "selfsigned";
	private static final String PRIVATE_KEY_ALIAS = "myprivkey";
	private static final String KEYSTORE = "cacerts";
	private static final String KEYSTORE_PASSWORD = "changeit";
	private static final int HASHSIZE = 32;
	private static final String KEYPATH = "pub.txt";
	public static final int SIGSIZE = 128;
	private byte[] id;
	private boolean debugMode ;


	private java.security.PublicKey _publicKey;
	private java.security.PrivateKey _privateKey;

	public BlockServerInterface _remote;

	public Library(boolean debug){
		debugMode = debug;
		getServerConnection();
		File f = new File(KEYPATH);
		if(f.exists()){
			_publicKey = getPubKeyFromFile();
			_privateKey= getPrivKeyFromFile();
		}else{
			FS_init();
		}
		id = getHash(Base64.getEncoder().encodeToString(_publicKey.getEncoded()).getBytes());
	}
	
	public byte[] getId(){
		return id;
	}
	
	public byte[] FS_init() {
		byte[] fileId = null;
		byte[] content = { (byte) 0 };
		getServerConnection();
		generateKeyPair();
		try {
			byte[] sig = makeSignature(content);
			fileId = _remote.put_k(content, sig, _publicKey);
		} catch (RemoteException | CantFindFileException | CantVerifySignatureException e) {
			e.printStackTrace();
		}
		return fileId;
	}

	private void getServerConnection() {
		Registry registry = null;
		try {
			registry = LocateRegistry.getRegistry("localhost", SERVER_PORT);
		} catch (RemoteException e) {
			System.out.println("Couldn't locate the registry");
			e.printStackTrace();
		}

		try {
			_remote = (BlockServerInterface) registry.lookup(SERVICE);
		} catch (RemoteException | NotBoundException e) {
			System.out.println("Couldn't get remote object");
			e.printStackTrace();
		}
	}

	public String readFromFile(String path) {
		BufferedReader br = null;
		String everything = null;
		try {
			br = new BufferedReader(new FileReader(path));
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			everything = sb.toString();
			br.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return everything;
	}

	private java.security.PrivateKey getPrivKeyFromFile() {

		PrivateKey Key = null;
		try {
			String KeyStr = readFromFile("priv.txt");
			byte[] KeyBytes = toDecodedBase64ByteArray(KeyStr.getBytes());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec KeySpec = new PKCS8EncodedKeySpec(KeyBytes);
			Key = keyFactory.generatePrivate(KeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return Key;
	}

	private java.security.PublicKey getPubKeyFromFile() {

		PublicKey Key = null;
		try {
			String KeyStr = readFromFile("pub.txt");
			byte[] KeyBytes = toDecodedBase64ByteArray(KeyStr.getBytes());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec KeySpec = new X509EncodedKeySpec(KeyBytes);
			Key = keyFactory.generatePublic(KeySpec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return Key;

	}

	public void generateKeyPair() {
		KeyPairGenerator keygen;
		try {
			keygen = KeyPairGenerator.getInstance("RSA");
			keygen.initialize(1024);
			KeyPair keypair = keygen.generateKeyPair();
			_publicKey = keypair.getPublic();
			_privateKey = keypair.getPrivate();

			storeKeys(_privateKey, _publicKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private void storeKeys(PrivateKey priv, PublicKey pub) {
		Writer writer = null;
		try {
			writer = new OutputStreamWriter(new FileOutputStream("priv.txt"), "utf-8");
			writer = new BufferedWriter(writer);
			writer.write(Base64.getEncoder().encodeToString(priv.getEncoded()));
			writer.close();

			writer = new OutputStreamWriter(new FileOutputStream("pub.txt"), "utf-8");
			writer = new BufferedWriter(writer);
			writer.write(Base64.getEncoder().encodeToString(pub.getEncoded()));
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	public byte[] makeSignature(byte[] data) {
		return encrypt(getHash(data), _privateKey);
	}

	private byte[] encrypt(byte[] buffer, java.security.Key key) {
		Cipher rsa;
		try {
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, key);
			return rsa.doFinal(buffer);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	private byte[] getHash(byte[] data) {
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

	private byte[] getBytesFromKey(java.security.Key key) {
		return Base64.getEncoder().encodeToString(key.getEncoded()).getBytes();
	}

	public void FS_write(int pos, int size, byte[] content) throws CantVerifySignatureException {
		getServerConnection();
		byte[] pkBlockAll = null;
		byte[] pkBlock = null;
		byte[] sig = null;
		byte[] fileId = getHash(getBytesFromKey(_publicKey));
		try {
			pkBlockAll = _remote.get(fileId);
			sig = Arrays.copyOfRange(pkBlockAll, 0, SIGSIZE);
			pkBlock = Arrays.copyOfRange(pkBlockAll, SIGSIZE, pkBlockAll.length);
			if(!checkSignature(pkBlock, sig, _publicKey)){
				throw new CantVerifySignatureException();
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		int numBlocks = pkBlock.length / HASHSIZE;
		int fileSize = numBlocks * SIZE;
		if (fileSize > pos) {
			double blockNum = Math.ceil(pos / SIZE) + 1;
			byte[] blockToGet = getBlockIdFromNumber(blockNum, pkBlock);
			try {
				byte[] prevContent = _remote.get(blockToGet);
				createNewBlocks(fileSize, pos, pkBlock, content, prevContent, blockNum, fileId, numBlocks);
			} catch (RemoteException e) {
				e.printStackTrace();
			}
		} else {
				createNewBlocks(fileSize, pos, pkBlock, content, fileId, numBlocks);
			
		}
	}

	private byte[] getBlockIdFromNumber(double blockNum, byte[] pkBlock) {
		int beg = (int) ((blockNum - 1) * HASHSIZE);
		int end = (int) (blockNum * HASHSIZE);
		byte[] blockToGet = Arrays.copyOfRange(pkBlock, beg, end);
		return blockToGet;
	}

	public void sendContentBlock(byte[] content, byte[] fileId) {
		byte[] contentBlock = new byte[content.length + fileId.length];
		System.arraycopy(fileId, 0, contentBlock, 0, fileId.length);
		System.arraycopy(content, 0, contentBlock, fileId.length, content.length);
		try {
			_remote.put_h(contentBlock);
		} catch (RemoteException | CantFindFileException e) {
			e.printStackTrace();
		}
	}

	public byte[] updatePKBlock(byte[] pkBlock, byte[] contentId, double blockNum) throws CantVerifySignatureException {
		int i;
		int startPos = (int) (blockNum - 1) * HASHSIZE;
		for (i = 0; i < contentId.length; i++) {
			pkBlock[startPos] = contentId[i];
			startPos++;
		}
		try {
			if(debugMode){
				byte[] corrupted = {(byte) 7};
				_remote.put_k(pkBlock, makeSignature(corrupted), _publicKey);
			}else{
				_remote.put_k(pkBlock, makeSignature(pkBlock), _publicKey);
			}
		} catch (RemoteException | CantFindFileException e) {
			e.printStackTrace();
		}
		return pkBlock;
	}

	public void createNewBlocks(int fileSize, int pos, byte[] pkBlock, byte[] content, byte[] prevContent,
			double blockNum, byte[] fileId, int numBlocks) throws CantVerifySignatureException {
		int i;
		int blockInitialPosition = (int) (blockNum - 1) * SIZE;
		int counter = pos - blockInitialPosition;
		for (i = 0; i < content.length; i++) {
			prevContent[counter] = content[i];
			counter++;
			if (counter == SIZE) {
				sendContentBlock(prevContent, fileId);
				if (blockNum > numBlocks) {

					pkBlock = updatePKBlock(pkBlock, getHash(prevContent));
					prevContent = new byte[SIZE];
				} else if (blockNum == numBlocks) {
					pkBlock = updatePKBlock(pkBlock, getHash(prevContent), blockNum);
					blockNum++;
					prevContent = new byte[SIZE];
				} else {
					try {
						pkBlock = updatePKBlock(pkBlock, getHash(prevContent), blockNum);
						blockNum++;
						prevContent = _remote.get(getBlockIdFromNumber(blockNum, pkBlock));
					} catch (RemoteException e) {
						e.printStackTrace();
					}
				}
				counter = 0;
			}
		}
		if (pos + content.length < fileSize) {
			sendContentBlock(prevContent, fileId);
			pkBlock = updatePKBlock(pkBlock, getHash(prevContent), blockNum);
		} else if (counter != 0) {
			while (counter != SIZE) {
				prevContent[counter] = (byte) 0;
				counter++;
			}
			sendContentBlock(prevContent, fileId);
			pkBlock = updatePKBlock(pkBlock, getHash(prevContent));
		}
	}

	public int FS_read(byte[] id, int pos, int size, byte[] content) throws CantVerifyContentException, BufferTooShortException, CantVerifySignatureException {
		if(content.length<size){
			throw new BufferTooShortException();
		}
		getServerConnection();
		int i;
		byte[] pkBlockAll = null;
		byte[] pkBlock = null;
		byte[] sig = null;
		try {
			pkBlockAll = _remote.get(id);
			sig = Arrays.copyOfRange(pkBlockAll, 0, SIGSIZE);
			pkBlock = Arrays.copyOfRange(pkBlockAll, SIGSIZE, pkBlockAll.length);
			if(!checkSignature(pkBlock, sig, _publicKey)){
				throw new CantVerifySignatureException();
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		int numBlocks = pkBlock.length / HASHSIZE;
		int fileSize = numBlocks * SIZE;
		if (pos < fileSize) {
			double blockNum = Math.ceil(pos / SIZE) + 1;
			byte[] blockToGet = getBlockIdFromNumber(blockNum, pkBlock);
			int blockPos = pos - ((int) (blockNum - 1) * SIZE);
			try {
				byte[] block = _remote.get(blockToGet);
				if (!checkHash(block, blockToGet)) {
					throw new CantVerifyContentException();
				}
				for (i = 0; i < size; i++) {
					content[i] = block[blockPos];
					blockPos++;
					if (blockPos == SIZE) {
						blockPos = 0;
						if (blockNum < numBlocks) {
							try {
								blockNum++;
								blockToGet = getBlockIdFromNumber(blockNum, pkBlock);
								block = _remote.get(blockToGet);
								if (!checkHash(block, blockToGet)) {
									throw new CantVerifyContentException();
								}
							} catch (RemoteException e) {
								e.printStackTrace();
							}
						} else {
							break;
						}
					}
				}
			} catch (RemoteException e) {
				e.printStackTrace();
			}

		}
		return content.length;
	}

	public byte[] updatePKBlock(byte[] pkBlock, byte[] id) throws CantVerifySignatureException {
		byte[] newPKBlock = new byte[pkBlock.length + HASHSIZE];
		if (pkBlock.length < HASHSIZE) {
			newPKBlock = id;
		} else {
			System.arraycopy(pkBlock, 0, newPKBlock, 0, pkBlock.length);
			System.arraycopy(id, 0, newPKBlock, pkBlock.length, id.length);
		}
		try {
			_remote.put_k(newPKBlock, makeSignature(newPKBlock), _publicKey);
		} catch (RemoteException | CantFindFileException e) {
			e.printStackTrace();
		}
		return newPKBlock;
	}

	public void createNewBlocks(int fileSize, int pos, byte[] pkBlock, byte[] content, byte[] fileId,
			double numBlocks) throws CantVerifySignatureException {
		byte[] contentToSend = new byte[SIZE];
		int counter = 0;
		int i;
		for (i = fileSize; i < pos; i++) {
			contentToSend[counter] = (byte) 0;
			counter++;
			if (counter == SIZE) {
				// send here and update pk and content block
				sendContentBlock(contentToSend, fileId);
				pkBlock = updatePKBlock(pkBlock, getHash(contentToSend));
				counter = 0;
			}
		}
		for (i = 0; i < content.length; i++) {
			contentToSend[counter] = content[i];
			counter++;
			if (counter == SIZE) {
				// send here and update pk and content block
				sendContentBlock(contentToSend, fileId);
				pkBlock = updatePKBlock(pkBlock, getHash(contentToSend));
				counter = 0;
			}
		}
		if (counter != 0) {
			while (counter != SIZE) {
				contentToSend[counter] = (byte) 0;
				counter++;
			}
			sendContentBlock(contentToSend, fileId);
			pkBlock = updatePKBlock(pkBlock, getHash(contentToSend));
			// send here and update pk and content block
		}
	}

	private static byte[] toDecodedBase64ByteArray(byte[] base64EncodedByteArray) {
		return DatatypeConverter.parseBase64Binary(new String(base64EncodedByteArray, Charset.forName("UTF-8")));
	}

	public boolean checkHash(byte[] content, byte[] id) {
		return Arrays.equals(getHash(content), id);
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