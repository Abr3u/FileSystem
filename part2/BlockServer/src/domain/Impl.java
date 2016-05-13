package domain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.Charset;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.xml.bind.DatatypeConverter;

import com.sun.javafx.iio.ImageFormatDescription.Signature;

import exceptions.CantVerifyCASignatureException;
import exceptions.CantVerifyChallengeException;
import exceptions.CantVerifySignatureException;
import exceptions.NoLongerValidCertificateException;
import sun.security.rsa.RSASignature.SHA256withRSA;

public class Impl extends UnicastRemoteObject implements BlockServerInterface {

	private static final int HASHSIZE = 32;
	private static final String ARRAY_FILE_NAME = "filesArray.ser";
	private static final String CERT_FILE_NAME = "certificates.ser";
	private static final int CHALLENGE_SIZE = 32;

	private ArrayList<BSFile> _files = new ArrayList<BSFile>();
	private ArrayList<X509Certificate> _certificates = new ArrayList<X509Certificate>();
	private int debugMode = 0;
	private HashMap<X509Certificate, ChallengeDetails> _challenges = new HashMap<X509Certificate, ChallengeDetails>();

	public Impl(int port) throws RemoteException, IllegalArgumentException {
		super(port);
		File f = new File(ARRAY_FILE_NAME);
		File f2 = new File(CERT_FILE_NAME);
		if (f.exists()) {
			readFilesFromSystem();
		}
		if (f2.exists()) {
			readCertFromSystem();
		}
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

	private void readCertFromSystem() {
		ArrayList<X509Certificate> array = null;
		try {
			FileInputStream fis = new FileInputStream(CERT_FILE_NAME);
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
		_certificates = new ArrayList<X509Certificate>();
		_certificates.addAll(array);
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
	public byte[] get(byte[] id) throws RemoteException {
		System.out.println("get @ BlackServer");
		for (BSFile file : _files) {
			if (file.containsBlock(id)) {
				if (debugMode == 1 && !file.getBlock(id).getClass().getName().contains("PK")) {
					byte[] corrupted = { (byte) 7 };
					return corrupted;
				} else {
					if (file.getBlock(id) instanceof domain.PKBlock) {
						PKBlock pk = (PKBlock) file.getBlock(id);
						byte[] returnContent = new byte[pk.getSignature().length + pk.getContent().length];
						System.arraycopy(pk.getSignature(), 0, returnContent, 0, pk.getSignature().length);
						System.arraycopy(pk.getContent(), 0, returnContent, pk.getSignature().length,
								pk.getContent().length);
						System.out.println(pk.getSignature().length);
						return returnContent;
					} else {
						return (file.getBlock(id)).getContent();
					}
				}
			}
		}
		return null;
	}

	private static byte[] toDecodedBase64ByteArray(byte[] base64EncodedByteArray) {
		return DatatypeConverter.parseBase64Binary(new String(base64EncodedByteArray, Charset.forName("UTF-8")));
	}

	@Override
	public byte[] put_k(byte[] data, byte[] signature,
			java.security.PublicKey public_key/*
												 * , byte[] recover, int pos,
												 * int size
												 */) throws CantVerifySignatureException {
		System.out.println("put_k @ BlackServer");
		BSFile file = null;
		if (!checkSignature(data, signature, public_key)) {
			throw new CantVerifySignatureException();
		}
		byte[] id = getHash(Base64.getEncoder().encodeToString(public_key.getEncoded()).getBytes());
		for (BSFile f : _files) {
			if (f.containsBlock(id)) {
				file = f;
			}
		}
		PKBlock pkBlock = new PKBlock(id, data, signature);
		if (file != null) {
			file.addBlock(pkBlock);
			System.out
					.println("Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
		} else {
			System.out
					.println("Adicionei PKBlock com id:\n" + Arrays.toString(id) + "\n e content size:" + data.length);
			file = new BSFile();
			file.addBlock(pkBlock);
			_files.add(file);
		}
		writeFilesToSystem();
		return id;
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

	public byte[] put_h(byte[] content) {
		System.out.println("put_h @ BlackServer");
		byte[] file_id = Arrays.copyOfRange(content, 0, HASHSIZE);
		byte[] file_content = Arrays.copyOfRange(content, HASHSIZE, content.length);
		byte[] id = getHash(file_content);
		ContentBlock block = new ContentBlock(id, file_content);
		for (BSFile file : _files) {
			if (file.containsBlock(file_id)) {
				file.addBlock(block);
				System.out.println("Adicionei HBlock com id:\n" + Arrays.toString(id) + "\n e content size:"
						+ file_content.length);
			}
		}
		return id;
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

	private boolean checkCASignature(byte[] data, byte[] signature, java.security.PublicKey public_key) {
		java.security.Signature sigObj;
		try {
			sigObj = java.security.Signature.getInstance("SHA1withRSA");
			sigObj.initVerify(public_key);
			sigObj.update(data);
			return sigObj.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return false;

	}

	@Override
	public ArrayList<PublicKey> readPubKeys() throws RemoteException {
		ArrayList<java.security.PublicKey> pubKeys = new ArrayList<java.security.PublicKey>();
		for (X509Certificate cert : _certificates) {
			pubKeys.add(cert.getPublicKey());
		}
		return pubKeys;
	}

	@Override
	public boolean storePubKey(X509Certificate certificate) throws RemoteException {
		boolean ok = _certificates.add(certificate);
		if (ok) {
			writeCertToSystem();
			return true;
		} else {
			return false;
		}
	}

	private void writeCertToSystem() {
		try {
			FileOutputStream fos = new FileOutputStream(CERT_FILE_NAME);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(_certificates);
			oos.close();
			fos.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	@Override
	public byte[] getChallenge(X509Certificate certificate, X509Certificate certificateCA)
			throws RemoteException, CantVerifyCASignatureException, NoLongerValidCertificateException {
		try {
			certificate.checkValidity();
			certificateCA.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e1) {
			throw new NoLongerValidCertificateException();
		}
		if (debugMode == 1) {

		InputStream inStream;
		X509Certificate badCA;
		try {
			inStream = new FileInputStream("cc1.cer");
			badCA = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inStream);
			inStream.close();
			certificate.verify(badCA.getPublicKey());
		} catch (IOException | CertificateException | InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {
			throw new CantVerifyCASignatureException();
		}
		} else {

		try {
			certificate.verify(certificateCA.getPublicKey());
		} catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			throw new CantVerifyCASignatureException();
		}
		// generate challenge
		Calendar cal = Calendar.getInstance(); // creates calendar
		cal.setTime(new Date()); // sets calendar time/date
		cal.add(Calendar.HOUR_OF_DAY, 1); // adds one hour
		Date expectedDate = cal.getTime();

		SecureRandom random = new SecureRandom();
		byte[] expected = new byte[CHALLENGE_SIZE];
		random.nextBytes(expected);

		ChallengeDetails mydet = new ChallengeDetails(expectedDate, expected);

		_challenges.put(certificate, mydet);
		return expected;
		}
		return null;
	}

	private byte[] encrypt(byte[] buffer, java.security.PublicKey key) {
		try {
			Cipher rsa;
			rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, key);
			return rsa.doFinal(buffer);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean solvedChallenge(X509Certificate cert, byte[] signedResponse)
			throws RemoteException, CantVerifyChallengeException {
		if (!_challenges.containsKey(cert)) {
			throw new RemoteException();
		}

		Calendar cal = Calendar.getInstance(); // creates calendar
		cal.setTime(new Date()); // sets calendar time/date
		Date now = cal.getTime();
		if (debugMode == 2) {
			now.setHours(now.getHours() + 2);
		}

		if (now.after(_challenges.get(cert).getValidUntil())) {
			throw new CantVerifyChallengeException();
		}
		if (!checkSignature(_challenges.get(cert).getExpected(), signedResponse, cert.getPublicKey())) {
			throw new CantVerifyChallengeException();
		}

		return true;
	}

	@Override
	public void setDebugMode(int b) throws RemoteException {
		debugMode = b;
	}

}