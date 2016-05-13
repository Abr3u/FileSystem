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
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.AlreadyBoundException;
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
import java.security.SecureRandom;
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
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.xml.bind.DatatypeConverter;

import exceptions.BufferTooShortException;
import exceptions.CantFindFileException;
import exceptions.CantVerifyContentException;
import exceptions.CantVerifyMACException;
import exceptions.CantVerifySignatureException;

public class Library {

	private static int CLIENTPORT = 9999;
	private static String CLIENTSERVICENAME = "CLIENTSERVICE";
	private static final int SERVER_PORT = 8888;
	private static final String SERVICE = "BlockServerService";
	private static final int SIZE = 2048;
	private static final int HASHSIZE = 32;
	private static final String KEYPATH = "pub.txt";
	private static final String SECRETPATH = "../BSServer/secret.txt";
	public static final int SIGSIZE = 128;
	private byte[] id;
	private int debugMode;
	private int _replicas;
	private int _fail;
	private byte[] _expectedBlock;
	private byte[] _expectedChallenge;

	private java.security.PublicKey _publicKey;
	private java.security.PrivateKey _privateKey;
	private javax.crypto.SecretKey _secret;

	private ArrayList<BlockServerInterface> _remotes = new ArrayList<BlockServerInterface>();

	// Register Variables

	private int wts = 0;
	private int acks = 0;
	private int rid = 0;
	private ArrayList<Map.Entry<Integer, byte[]>> readList = new ArrayList<Map.Entry<Integer, byte[]>>();
	private boolean enoughAcks = false;
	private boolean enoughReads = false;

	public void setEnoughReads(boolean b) {
		enoughReads = b;
	}

	public byte[] getExpectedChallenge() {
		return _expectedChallenge;
	}

	public Library(int replicas, int debug) throws CantVerifyMACException {
		_replicas = replicas;
		_fail = (_replicas - 1) / 3;
		debugMode = debug;
		try {
			publishClientConnection();
		} catch (RemoteException | AlreadyBoundException e) {
			e.printStackTrace();
		}
		getServerConnection();
		_secret = getSecretFromFile();
		File f = new File(KEYPATH);
		if (f.exists()) {
			_publicKey = getPubKeyFromFile();
			_privateKey = getPrivKeyFromFile();
		} else {
			FS_init();
		}
		id = getHash(Base64.getEncoder().encodeToString(_publicKey.getEncoded()).getBytes());
	}

	private void publishClientConnection() throws RemoteException, AlreadyBoundException {
		ClientService cs = new ClientService(this);

		LocateRegistry.createRegistry(CLIENTPORT);

		Registry registry = LocateRegistry.getRegistry("localhost", CLIENTPORT);

		registry.bind(CLIENTSERVICENAME, cs);

		System.out.println("Client running on port: " + CLIENTPORT);

	}

	public byte[] getId() {
		return id;
	}

	public void FS_init() throws CantVerifyMACException {
		byte[] content = { (byte) 0 };
		getServerConnection();
		generateKeyPair();
		try {
			byte[] sig = makeSignature(content);
			broadcastPutK(content, sig, _publicKey);
			waitforAcks();
		} catch (RemoteException | CantFindFileException | CantVerifySignatureException e) {
			e.printStackTrace();
		}
	}

	private void broadcastPutK(byte[] content, byte[] sig, java.security.PublicKey PK)
			throws RemoteException, CantFindFileException, CantVerifySignatureException, CantVerifyMACException {

		wts = wts + 1;
		acks = 0;
		_expectedChallenge = generateRandom();
		for (BlockServerInterface remote : _remotes) {
			byte[] wtsB = ByteBuffer.allocate(4).putInt(wts).array();
			byte[] encoded = PK.getEncoded();
			byte[] toHash = new byte[content.length + sig.length + encoded.length + wtsB.length
					+ _expectedChallenge.length];
			System.arraycopy(content, 0, toHash, 0, content.length);
			System.arraycopy(sig, 0, toHash, content.length, sig.length);
			System.arraycopy(encoded, 0, toHash, content.length + sig.length, encoded.length);
			System.arraycopy(wtsB, 0, toHash, content.length + sig.length + encoded.length, wtsB.length);
			System.arraycopy(_expectedChallenge, 0, toHash, content.length + sig.length + encoded.length + wtsB.length,
					_expectedChallenge.length);

			byte[] hash = getMAC(toHash);
			if (debugMode == 2) {
				remote.put_k(content, sig, PK, wts, new byte[] { (byte) 5 }, _expectedChallenge);
			} else {
				remote.put_k(content, sig, PK, wts, hash, _expectedChallenge);
			}
		}
		// return fileId;
	}

	private byte[] generateRandom() {
		SecureRandom random = new SecureRandom();
		byte[] expected = new byte[128];
		random.nextBytes(expected);
		return expected;
	}

	private void broadcastPutH(byte[] content) throws RemoteException, CantFindFileException, CantVerifyMACException {
		wts = wts + 1;
		acks = 0;
		_expectedChallenge = generateRandom();
		HashSet<BlockServerInterface> quorum = getQuorumContentBlocks();
		for (BlockServerInterface remote : quorum) {
			byte[] wtsB = ByteBuffer.allocate(4).putInt(wts).array();
			byte[] toHash = new byte[content.length + wtsB.length + _expectedChallenge.length];
			System.arraycopy(content, 0, toHash, 0, content.length);
			System.arraycopy(wtsB, 0, toHash, content.length, wtsB.length);
			System.arraycopy(_expectedChallenge, 0, toHash, content.length + wtsB.length, _expectedChallenge.length);

			byte[] hash = getMAC(toHash);
			remote.put_h(content, wts, hash, _expectedChallenge);
		}

	}

	private HashSet<BlockServerInterface> getQuorumContentBlocks() {
		HashSet<BlockServerInterface> res = new HashSet<BlockServerInterface>();
		int n = _fail + 2;
		HashSet<Integer> lastRandoms = new HashSet<Integer>();
		Random randomGen = new Random();
		while (n > 0) {
			int index = randomGen.nextInt(_replicas);
			if (lastRandoms.add(index)) {// success no duplicate random
				res.add(_remotes.get(index));
				n--;
			}
		}
		return res;
	}

	private void getServerConnection() {
		int i;
		for (i = 0; i < _replicas; i++) {

			// RMIwithSSL(SERVER_PORT+i);

			Registry registry = null;
			try {
				registry = LocateRegistry.getRegistry("localhost", SERVER_PORT + i);
			} catch (RemoteException e) {
				System.out.println("Couldn't locate the registry");
				e.printStackTrace();
			}

			try {
				_remotes.add((BlockServerInterface) registry.lookup(SERVICE));
			} catch (RemoteException | NotBoundException e) {
				System.out.println("Couldn't get remote object");
				e.printStackTrace();
			}
		}
	}

	private void RMIwithSSL(int port) {
		System.setProperty("javax.net.ssl.trustStore",
				"C:\\Users\\Lucília\\Documents\\GitHub\\SecProject3\\BSClient\\src\\truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "password");
		System.setProperty("javax.net.ssl.trustStore",
				"C:\\Users\\Lucï¿½lia\\Documents\\GitHub\\SecProject3\\BSClient\\src\\truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "password");

		Registry registry;
		try {
			registry = LocateRegistry.getRegistry("localhost", port, new SslRMIClientSocketFactory());

			_remotes.add((BlockServerInterface) registry.lookup(SERVICE));
		} catch (RemoteException | NotBoundException e) {
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

	public byte[] getMAC(byte[] data) {
		try {
			Mac mac = Mac.getInstance(_secret.getAlgorithm());
			mac.init(_secret);
			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;

	}

	private SecretKey getSecretFromFile() {

		String KeyStr = readFromFile(SECRETPATH);
		byte[] KeyBytes = toDecodedBase64ByteArray(KeyStr.getBytes());
		SecretKey Key = new SecretKeySpec(KeyBytes, "HmacMD5");
		return Key;
	}

	public byte[] getHash(byte[] data) {
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

	private void broadcastGet(byte[] id) throws RemoteException, CantVerifyMACException {
		rid = rid + 1;
		readList.clear();
		_expectedChallenge = generateRandom();
		for (BlockServerInterface remote : _remotes) {
			byte[] ridB = ByteBuffer.allocate(4).putInt(rid).array();
			byte[] toHash = new byte[id.length + ridB.length + _expectedChallenge.length];
			System.arraycopy(id, 0, toHash, 0, id.length);
			System.arraycopy(ridB, 0, toHash, id.length, ridB.length);
			System.arraycopy(_expectedChallenge, 0, toHash, id.length, _expectedChallenge.length);
			byte[] hash = getMAC(toHash);
			remote.get(id, rid, hash, _expectedChallenge);
		}
	}

	public void FS_write(int pos, int size, byte[] content)
			throws CantVerifySignatureException, CantVerifyMACException {
		getServerConnection();
		byte[] pkBlockAll = null;
		byte[] pkBlock = null;
		byte[] sig = null;
		byte[] fileId = getHash(getBytesFromKey(_publicKey));
		try {
			broadcastGet(fileId);
			pkBlockAll = waitForReads();
			sig = Arrays.copyOfRange(pkBlockAll, 0, SIGSIZE);
			pkBlock = Arrays.copyOfRange(pkBlockAll, SIGSIZE, pkBlockAll.length);
			if (!checkSignature(pkBlock, sig, _publicKey)) {
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
			_expectedBlock = blockToGet;
			try {
				broadcastGet(blockToGet);
				byte[] prevContent = waitForReads();
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
			broadcastPutH(contentBlock);
			waitforAcks();
		} catch (RemoteException | CantFindFileException | CantVerifyMACException e) {
			e.printStackTrace();
		}
	}

	public byte[] updatePKBlock(byte[] pkBlock, byte[] contentId, double blockNum)
			throws CantVerifySignatureException, CantVerifyMACException {
		int i;
		int startPos = (int) (blockNum - 1) * HASHSIZE;
		for (i = 0; i < contentId.length; i++) {
			pkBlock[startPos] = contentId[i];
			startPos++;
		}
		try {
			if (debugMode == 1) {
				byte[] corrupted = { (byte) 7 };
				broadcastPutK(pkBlock, makeSignature(corrupted), _publicKey);
				waitforAcks();
			} else {
				broadcastPutK(pkBlock, makeSignature(pkBlock), _publicKey);
				waitforAcks();
			}
		} catch (RemoteException | CantFindFileException e) {
			e.printStackTrace();
		}
		return pkBlock;
	}

	public void createNewBlocks(int fileSize, int pos, byte[] pkBlock, byte[] content, byte[] prevContent,
			double blockNum, byte[] fileId, int numBlocks) throws CantVerifySignatureException, CantVerifyMACException {
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
						_expectedBlock = getBlockIdFromNumber(blockNum, pkBlock);
						broadcastGet(_expectedBlock);
						prevContent = waitForReads();
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

	public int FS_read(byte[] id, int pos, int size, byte[] content) throws CantVerifyContentException,
			BufferTooShortException, CantVerifySignatureException, CantVerifyMACException {
		if (content.length < size) {
			throw new BufferTooShortException();
		}
		getServerConnection();
		int i;
		byte[] pkBlockAll = null;
		byte[] pkBlock = null;
		byte[] sig = null;
		try {
			broadcastGet(id);
			pkBlockAll = waitForReads();
			sig = Arrays.copyOfRange(pkBlockAll, 0, SIGSIZE);
			pkBlock = Arrays.copyOfRange(pkBlockAll, SIGSIZE, pkBlockAll.length);
			if (!checkSignature(pkBlock, sig, _publicKey)) {
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
			_expectedBlock = blockToGet;
			int blockPos = pos - ((int) (blockNum - 1) * SIZE);
			try {
				broadcastGet(blockToGet);
				byte[] block = waitForReads();
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
								_expectedBlock = blockToGet;
								broadcastGet(blockToGet);
								block = waitForReads();
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

	private byte[] waitForReads() {
		while (!enoughReads) {
		}
		enoughReads = false;
		return highestValue();
	}

	private byte[] highestValue() {
		int highValue = -1;
		byte[] highValueContent = null;
		for (Map.Entry<Integer, byte[]> entry : readList) {
			if (entry.getKey() > highValue) {
				highValue = entry.getKey();
				highValueContent = entry.getValue();
			}
		}
		readList.clear();
		return highValueContent;
	}

	public byte[] updatePKBlock(byte[] pkBlock, byte[] id) throws CantVerifySignatureException, CantVerifyMACException {
		byte[] newPKBlock = new byte[pkBlock.length + HASHSIZE];
		if (pkBlock.length < HASHSIZE) {
			newPKBlock = id;
		} else {
			System.arraycopy(pkBlock, 0, newPKBlock, 0, pkBlock.length);
			System.arraycopy(id, 0, newPKBlock, pkBlock.length, id.length);
		}
		try {
			broadcastPutK(newPKBlock, makeSignature(newPKBlock), _publicKey);
			waitforAcks();
		} catch (RemoteException | CantFindFileException e) {
			e.printStackTrace();
		}
		return newPKBlock;
	}

	public void createNewBlocks(int fileSize, int pos, byte[] pkBlock, byte[] content, byte[] fileId, double numBlocks)
			throws CantVerifySignatureException, CantVerifyMACException {
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

		if (Arrays.equals(digest, decrypted)) {
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

	public void incrementAcks() {
		acks++;
		if (acks > ((_replicas + _fail) / 2)) {
			acks = 0;
			enoughAcks = true;
		}
	}

	public void incrementAcksH() {
		acks++;
		if (acks > _fail) {
			acks = 0;
			enoughAcks = true;
		}
	}

	public void waitforAcks() {
		while (!enoughAcks) {
		}
		enoughAcks = false;
	}

	public int getLastWTS() {
		return wts;
	}

	public int getLastRid() {
		return rid;
	}

	public void addRead(int ts, byte[] content) {
		readList.add(new AbstractMap.SimpleEntry<>(ts, content));
		if (readList.size() > ((_replicas + _fail) / 2)) {
			enoughReads = true;
		}
	}

	public boolean checkContentBlockIntegrity(byte[] content) {
		return Arrays.equals(_expectedBlock, getHash(content));
	}
}