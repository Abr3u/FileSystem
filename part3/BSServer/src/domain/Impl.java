package domain;

import java.awt.image.ByteLookupTable;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import exceptions.CantVerifyMACException;
import exceptions.CantVerifySignatureException;

public class Impl extends UnicastRemoteObject implements BlockServerInterface {

	private static final int HASHSIZE = 32;
	private static final String ARRAY_FILE_NAME = "filesArray.ser";
	private static final int CLIENT_PORT = 9999;
	private static final String SERVICE = "CLIENTSERVICE";
	private static final String SECRETPATH = "secret.txt";
	private ArrayList<BSFile> _files = new ArrayList<BSFile>();
	private int debugMode;
	private javax.crypto.SecretKey _secret;
	private byte[] _returnChallenge;
	private int _myport;

	public Impl(int port, int debug) throws RemoteException, IllegalArgumentException {
		super(port);
		_myport = port;
		debugMode = debug;
		File f = new File(ARRAY_FILE_NAME);
		if (f.exists()) {
			readFilesFromSystem();
		}
		f = new File(SECRETPATH);
		if (!f.exists()) {
			generateSecret();
		}
		_secret = getSecretFromFile();
	}

	public void generateSecret() {
		KeyGenerator keyGenerator;
		try {
			keyGenerator = KeyGenerator.getInstance("HmacMD5");
			SecretKey secret = keyGenerator.generateKey();
			storeSecret(secret);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	private void storeSecret(SecretKey key) {
		Writer writer = null;
		try {
			writer = new OutputStreamWriter(new FileOutputStream("secret.txt"), "utf-8");
			writer = new BufferedWriter(writer);
			writer.write(Base64.getEncoder().encodeToString(key.getEncoded()));
			writer.close();
		} catch (IOException e) {
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

	private SecretKey getSecretFromFile() {

		String KeyStr = readFromFile(SECRETPATH);
		byte[] KeyBytes = toDecodedBase64ByteArray(KeyStr.getBytes());
		SecretKey Key = new SecretKeySpec(KeyBytes, "HmacMD5");
		return Key;
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
	
	private ClientInterface getClientConnection() {
		Registry registry = null;
		try {
			registry = LocateRegistry.getRegistry("localhost", CLIENT_PORT);
		} catch (RemoteException e) {
			System.out.println("Couldn't locate the registry");
			e.printStackTrace();
		}

		try {
			return (ClientInterface) registry.lookup(SERVICE);
		} catch (RemoteException | NotBoundException e) {
			System.out.println("Couldn't get remote object");
			e.printStackTrace();
		}
		return null;
	}

	private void writeFilesToSystem() {
		try {
			FileOutputStream fos = new FileOutputStream(ARRAY_FILE_NAME);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(_files);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	private void readFilesFromSystem() {
		ArrayList<BSFile> array = null;
		try {
			FileInputStream fis = new FileInputStream(ARRAY_FILE_NAME);
			ObjectInputStream ois = new ObjectInputStream(fis);
			array = (ArrayList) ois.readObject();
			ois.close();
			fis.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} catch (ClassNotFoundException c) {
			System.out.println("Class not found");
			c.printStackTrace();
		}
		_files = new ArrayList<BSFile>();
		_files.addAll(array);
	}

	@Override
	public void get(byte[] id, int rid, byte[] hash,byte[] challenge) throws RemoteException, CantVerifyMACException {
		System.out.println("get @ BlackServer "+_myport);

		byte[] ridB = ByteBuffer.allocate(4).putInt(rid).array();
		byte[] toHash = new byte[id.length+ridB.length+challenge.length];
		System.arraycopy(id, 0, toHash, 0, id.length);
		System.arraycopy(ridB, 0, toHash,id.length , ridB.length);
		System.arraycopy(challenge, 0, toHash,id.length , challenge.length);
		
		byte[] expectedHash = getMAC(toHash);

		if (!Arrays.equals(expectedHash, hash)) {
			throw new CantVerifyMACException();
		}

		_returnChallenge = challenge;
		
		ClientInterface client = getClientConnection();
		for (BSFile file : _files) {
			if (file.containsBlock(id)) {
				if (file.getBlock(id) instanceof domain.PKBlock) {
					PKBlock pk = (PKBlock) file.getBlock(id);
					byte[] returnContent = new byte[pk.getSignature().length + pk.getContent().length];
					System.arraycopy(pk.getSignature(), 0, returnContent, 0, pk.getSignature().length);
					System.arraycopy(pk.getContent(), 0, returnContent, pk.getSignature().length,
							pk.getContent().length);
					System.out.println(pk.getSignature().length);
					
					byte[] wtsB = ByteBuffer.allocate(4).putInt(pk.get_wts()).array();
					ridB = ByteBuffer.allocate(4).putInt(rid).array();
					toHash = new byte[ridB.length + returnContent.length + wtsB.length+_returnChallenge.length];
					System.arraycopy(ridB, 0, toHash, 0, ridB.length);
					System.arraycopy(returnContent, 0, toHash, ridB.length, returnContent.length);
					System.arraycopy(wtsB, 0, toHash, ridB.length + returnContent.length, wtsB.length);
					System.arraycopy(_returnChallenge, 0, toHash, ridB.length + returnContent.length+wtsB.length, _returnChallenge.length);
					byte[] hashToSend = getMAC(toHash);
					if (debugMode == 2) {
						return;
					} else if (debugMode == 1) {
						client.receivePKBlock(rid + 200, returnContent, pk.get_wts(), hashToSend);
					} else {
						client.receivePKBlock(rid, returnContent, pk.get_wts(), hashToSend);
					}
					return;
				} else {
					ridB = ByteBuffer.allocate(4).putInt(rid).array();
					byte[] contentBlockSend = (file.getBlock(id)).getContent();
					byte[] wtsB = ByteBuffer.allocate(4).putInt(file.getBlock(id).get_wts()).array();
					toHash = new byte[ridB.length + contentBlockSend.length + wtsB.length+_returnChallenge.length];
					System.arraycopy(ridB, 0, toHash, 0, ridB.length);
					System.arraycopy(contentBlockSend, 0, toHash, ridB.length, contentBlockSend.length);
					System.arraycopy(wtsB, 0, toHash, ridB.length + contentBlockSend.length, wtsB.length);
					System.arraycopy(_returnChallenge, 0, toHash, ridB.length + contentBlockSend.length+wtsB.length, _returnChallenge.length);
					byte[] hashToSend = getMAC(toHash);
					if (debugMode == 2) {
						return;
					} else if (debugMode == 1) {
						client.receiveContentBlock(rid + 200, contentBlockSend, file.getBlock(id).get_wts(),
								hashToSend);
					} else {
						client.receiveContentBlock(rid, contentBlockSend, file.getBlock(id).get_wts(), hashToSend);
					}
					return;
				}
			}
		}
		client.receiveContentBlock(rid, null, -1, new byte[1]);
	}

	private static byte[] toDecodedBase64ByteArray(byte[] base64EncodedByteArray) {
		return DatatypeConverter.parseBase64Binary(new String(base64EncodedByteArray, Charset.forName("UTF-8")));
	}

	@Override
	public void put_k(byte[] data, byte[] signature, java.security.PublicKey public_key, int wts, byte[] hash, byte[]challenge)
			throws CantVerifySignatureException, CantVerifyMACException, RemoteException {
		System.out.println("put_k @ BlackServer "+_myport);
		
		byte[] wtsB = ByteBuffer.allocate(4).putInt(wts).array();
		byte[] encoded = public_key.getEncoded();
		byte[] toHash = new byte[data.length+signature.length+encoded.length+wtsB.length+challenge.length];
		System.arraycopy(data, 0, toHash, 0, data.length);
		System.arraycopy(signature, 0, toHash, data.length, signature.length);
		System.arraycopy(encoded, 0, toHash, data.length+signature.length, encoded.length);
		System.arraycopy(wtsB, 0, toHash,data.length+signature.length+encoded.length , wtsB.length);
		System.arraycopy(challenge, 0, toHash,data.length+signature.length+encoded.length+wtsB.length
				, challenge.length);
		byte[] hashExpected = getMAC(toHash);

		if (!Arrays.equals(hashExpected, hash)) {
			throw new CantVerifyMACException();
		}

		_returnChallenge = challenge;
		
		ClientInterface client = getClientConnection();
		BSFile file = null;
		System.out.println("PKBLOCK " + Arrays.toString(data));
		if (!checkSignature(data, signature, public_key)) {
			throw new CantVerifySignatureException();
		}
		byte[] id = getHash(Base64.getEncoder().encodeToString(public_key.getEncoded()).getBytes());
		for (BSFile f : _files) {
			if (f.containsBlock(id)) {
				file = f;
			}
		}
		// PKBlock pkBlock = new PKBlock(id, data, signature);
		if (file != null) {
			if (file.getBlock(id).get_wts() < wts) {
				PKBlock pkBlock = new PKBlock(id, data, signature, wts);
				file.addBlock(pkBlock);
				System.out.println(
						"Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
			}
		} else {
			PKBlock pkBlock = new PKBlock(id, data, signature, wts);
			System.out
					.println("Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
			file = new BSFile();
			file.addBlock(pkBlock);
			_files.add(file);
		}
		writeFilesToSystem();
		wtsB = ByteBuffer.allocate(4).putInt(wts).array();
		toHash = new byte[wtsB.length+_returnChallenge.length];
		System.arraycopy(wtsB, 0, toHash, 0, wtsB.length);
		System.arraycopy(_returnChallenge, 0, toHash, wtsB.length, _returnChallenge.length);
		byte[] hashToSend = getMAC(toHash);
		if (debugMode == 2) {
			return;
		} else if (debugMode == 1) {
			client.receiveAck(wts + 200, hashToSend);
		} else {
			client.receiveAck(wts, hashToSend);
		}
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

	@Override
	public void put_h(byte[] content, int wts, byte[] hash,byte[] challenge) throws RemoteException, CantVerifyMACException {
		System.out.println("put_h @ BlackServer "+_myport);

		
		byte[] wtsB = ByteBuffer.allocate(4).putInt(wts).array();
		byte[] toHash = new byte[content.length+wtsB.length+challenge.length];
		System.arraycopy(content, 0, toHash, 0, content.length);
		System.arraycopy(wtsB, 0, toHash,content.length , wtsB.length);
		System.arraycopy(challenge, 0, toHash,content.length+wtsB.length, challenge.length);
		
		byte[] expectedHash = getMAC(toHash);

		if (!Arrays.equals(expectedHash, hash)) {
			throw new CantVerifyMACException();
		}

		_returnChallenge = challenge;
		
		ClientInterface client = getClientConnection();
		byte[] file_id = Arrays.copyOfRange(content, 0, HASHSIZE);
		byte[] file_content = Arrays.copyOfRange(content, HASHSIZE, content.length);
		byte[] id = getHash(file_content);
		ContentBlock block = new ContentBlock(id, file_content, wts);
		for (BSFile file : _files) {
			if (file.containsBlock(file_id)) {
				file.addBlock(block);
				System.out.println("Adicionei HBlock com id:\n" + Arrays.toString(id) + "\n e content size:"
						+ file_content.length);
			}
		}
		wtsB = ByteBuffer.allocate(4).putInt(wts).array();
		toHash = new byte[wtsB.length+_returnChallenge.length];
		System.arraycopy(wtsB, 0, toHash, 0, wtsB.length);
		System.arraycopy(_returnChallenge, 0, toHash, wtsB.length, _returnChallenge.length);
		byte[] hashToSend = getMAC(toHash);
		if (debugMode == 2) {
			return;
		} else if (debugMode == 1) {
			client.receiveAckH(wts + 200, hashToSend);
		} else {
			client.receiveAckH(wts, hashToSend);
		}
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
}