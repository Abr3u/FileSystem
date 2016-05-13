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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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
import java.security.cert.X509Certificate;
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
import javax.naming.BinaryRefAddr;
import javax.xml.bind.DatatypeConverter;

import com.sun.corba.se.spi.orbutil.fsm.Guard.Result;
import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader.Array;

import exceptions.BufferTooShortException;
import exceptions.CantFindFileException;
import exceptions.CantStorePubKeyException;
import exceptions.CantVerifyCASignatureException;
import exceptions.CantVerifyChallengeException;
import exceptions.CantVerifyContentException;
import exceptions.CantVerifySignatureException;
import exceptions.NoLongerValidCertificateException;
import pteidlib.PTEID_Certif;
import pteidlib.PteidException;
import pteidlib.pteid;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

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
	private static String libName = "libpteidpkcs11.so";
	private byte[] id;
	private int debugMode;

	private X509Certificate certificate;
	private java.security.PublicKey _publicKey;

	public BlockServerInterface _remote;

	public Library(int debug) throws RemoteException {
		debugMode = debug;
		getServerConnection();
		checkOS();
		try {
			System.loadLibrary("pteidlibj");
			pteid.Init("");
			pteid.SetSODChecking(false);
		} catch (PteidException e) {
			e.printStackTrace();
		}
		try {
			certificate = getCertificateFromByteArray(getAuthorizationCertificate(0));
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		_publicKey = certificate.getPublicKey();
		ArrayList<java.security.PublicKey> pubKeys = _remote.readPubKeys();
		if (!pubKeys.contains(_publicKey)) {
			try {
				FS_init();
			} catch (CantStorePubKeyException | CantVerifyCASignatureException | CantVerifyChallengeException e) {
				e.printStackTrace();
			}
		}
	}

	private void checkOS() {
		String osName = System.getProperty("os.name");
		if (-1 != osName.indexOf("Windows"))
			libName = "pteidpkcs11.dll";
		else if (-1 != osName.indexOf("Mac"))
			libName = "pteidpkcs11.dylib";
	}

	public PKCS11 getPKCS11() throws ClassNotFoundException, NoSuchMethodException, SecurityException,
			IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		PKCS11 pkcs11;
		String javaVersion = System.getProperty("java.version");
		Class pkcs11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
		if (javaVersion.startsWith("1.5.")) {
			Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
					new Class[] { String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
			pkcs11 = (PKCS11) getInstanceMethode.invoke(null, new Object[] { libName, null, false });
		} else {
			Method getInstanceMethode = pkcs11Class.getDeclaredMethod("getInstance",
					new Class[] { String.class, String.class, CK_C_INITIALIZE_ARGS.class, boolean.class });
			pkcs11 = (PKCS11) getInstanceMethode.invoke(null,
					new Object[] { libName, "C_GetFunctionList", null, false });
		}
		return pkcs11;
	}

	private static X509Certificate getCertificateFromByteArray(byte[] certificateEncoded) throws CertificateException {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certificateEncoded);
		X509Certificate cert = (X509Certificate) f.generateCertificate(in);
		return cert;
	}

	private static byte[] getAuthorizationCertificate(int n) {
		byte[] certificate = null;
		try {
			PTEID_Certif[] certs = pteid.GetCertificates();
			certificate = certs[n].certif;
		} catch (PteidException e) {
			e.printStackTrace();
		}
		return certificate;
	}

	public byte[] makeSig(byte[] content) {
		PKCS11 pkcs11 = null;
		byte[] sig = new byte[2048];
		try {
			pkcs11 = getPKCS11();
			long p11_session = pkcs11.C_OpenSession(0, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
			pkcs11.C_Login(p11_session, 1, null);
			CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[1];
			attributes[0] = new CK_ATTRIBUTE();
			attributes[0].type = PKCS11Constants.CKA_CLASS;
			attributes[0].pValue = new Long(PKCS11Constants.CKO_PRIVATE_KEY);
			pkcs11.C_FindObjectsInit(p11_session, attributes);
			long[] keyHandles = pkcs11.C_FindObjects(p11_session, 5);
			long signatureKey = keyHandles[0];
			pkcs11.C_FindObjectsFinal(p11_session);

			CK_MECHANISM mechanism = new CK_MECHANISM();
			mechanism.mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
			mechanism.pParameter = null;
			pkcs11.C_SignInit(p11_session, mechanism, signatureKey);
			sig = pkcs11.C_Sign(p11_session, content);
			pkcs11.C_CloseSession(p11_session);
		} catch (PKCS11Exception | ClassNotFoundException | NoSuchMethodException | SecurityException
				| IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			e.printStackTrace();
		}
		return sig;
	}

	public byte[] getId() {
		return id;
	}

	public void FS_init()
			throws CantStorePubKeyException, CantVerifyCASignatureException, CantVerifyChallengeException {
		byte[] content = { (byte) 0 };
		getServerConnection();
		try {
			if (debugMode==1) {
				InputStream inStream;
				try {
					inStream = new FileInputStream("cc1.cer");
					certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inStream);
					inStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			} 
			X509Certificate CAcert = getCertificateFromByteArray(getAuthorizationCertificate(3));
			byte[] challenge = _remote.getChallenge(certificate, CAcert);
			byte[] solvedChallenge = makeSig(challenge);
			if(debugMode==2){
				byte[] corrupted = new byte[128];
				Arrays.fill(corrupted, (byte) 8);
				solvedChallenge = corrupted;
			}
			
			_remote.solvedChallenge(certificate, solvedChallenge);

			_remote.storePubKey(certificate);

			byte[] sig = makeSig(content);
			_remote.put_k(content, sig, _publicKey);
		} catch (RemoteException | CantFindFileException | CertificateException | NoLongerValidCertificateException |CantVerifyCASignatureException  e) {
			//e.printStackTrace();
			 throw new CantStorePubKeyException();
		} catch (CantVerifySignatureException e) {
			e.printStackTrace();
		}
	}

	public ArrayList<java.security.PublicKey> FS_List() throws RemoteException {
		getServerConnection();
		return _remote.readPubKeys();
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
		// try {
		// if (debugMode) {
		// byte[] corrupted = { (byte) 7 };
		// _remote.put_k(pkBlock, makeSig(corrupted), _publicKey);
		// } else {
		// _remote.put_k(pkBlock, makeSig(pkBlock), _publicKey);
		// }
		// } catch (RemoteException | CantFindFileException e) {
		// e.printStackTrace();
		// }
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
		try {
			if (debugMode==1) {
				byte[] fakeSig = new byte[128];
				Arrays.fill(fakeSig, (byte) 5);
				_remote.put_k(pkBlock, fakeSig, _publicKey);
			} else {
				_remote.put_k(pkBlock, makeSig(pkBlock), _publicKey);
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (CantFindFileException e) {
			e.printStackTrace();
		}
	}

	public byte[] FS_read(PublicKey pubKey, int pos, int size, byte[] content)
			throws CantVerifyContentException, BufferTooShortException, CantVerifySignatureException {
		if (content.length < size) {
			throw new BufferTooShortException();
		}
		getServerConnection();
		int i;
		byte[] pkBlockAll = null;
		byte[] pkBlock = null;
		byte[] sig = null;
		byte[] toRead = getHash(getBytesFromKey(pubKey));
		try {
			pkBlockAll = _remote.get(toRead);
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
		return content;
	}

	public byte[] updatePKBlock(byte[] pkBlock, byte[] id) throws CantVerifySignatureException {
		byte[] newPKBlock = new byte[pkBlock.length + HASHSIZE];
		if (pkBlock.length < HASHSIZE) {
			newPKBlock = id;
		} else {
			System.arraycopy(pkBlock, 0, newPKBlock, 0, pkBlock.length);
			System.arraycopy(id, 0, newPKBlock, pkBlock.length, id.length);
		}
		// try {
		// _remote.put_k(newPKBlock, makeSig(newPKBlock), _publicKey);
		// } catch (RemoteException | CantFindFileException e) {
		// e.printStackTrace();
		// }
		return newPKBlock;
	}

	public void createNewBlocks(int fileSize, int pos, byte[] pkBlock, byte[] content, byte[] fileId, double numBlocks)
			throws CantVerifySignatureException {
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
		try {
			if (debugMode==1) {
				byte[] fakeSig = new byte[128];
				Arrays.fill(fakeSig, (byte) 5);
				_remote.put_k(pkBlock, fakeSig, _publicKey);
			} else {
				_remote.put_k(pkBlock, makeSig(pkBlock), _publicKey);
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (CantFindFileException e) {
			e.printStackTrace();
		}
	}

	private static byte[] toDecodedBase64ByteArray(byte[] base64EncodedByteArray) {
		return DatatypeConverter.parseBase64Binary(new String(base64EncodedByteArray, Charset.forName("UTF-8")));
	}

	public boolean checkHash(byte[] content, byte[] id) {
		return Arrays.equals(getHash(content), id);
	}

	private boolean checkSignature(byte[] data, byte[] signature, java.security.PublicKey public_key) {
		java.security.Signature sigObj;
		try {
			sigObj = java.security.Signature.getInstance("SHA256withRSA");
			sigObj.initVerify(public_key);
			sigObj.update(data);
			return sigObj.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
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

	public void setDebugModeServer(int b) throws RemoteException {
		getServerConnection();
		_remote.setDebugMode(b);
	}
}