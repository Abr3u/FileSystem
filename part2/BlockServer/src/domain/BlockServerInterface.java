package domain;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import exceptions.CantFindFileException;
import exceptions.CantVerifyCASignatureException;
import exceptions.CantVerifyChallengeException;
import exceptions.CantVerifySignatureException;
import exceptions.NoLongerValidCertificateException;

public interface BlockServerInterface extends Remote{
	
	byte[] get(byte[] id) throws RemoteException;
	byte[] put_k(byte[] data, byte[] signature, java.security.PublicKey public_key) throws RemoteException, CantFindFileException, CantVerifySignatureException;
	byte[] put_h(byte[] data) throws RemoteException, CantFindFileException;
	ArrayList<PublicKey> readPubKeys() throws RemoteException;
	boolean storePubKey(X509Certificate certificate) throws RemoteException;
	byte[] getChallenge(X509Certificate certificate,X509Certificate certificateCA)throws RemoteException, CantVerifyCASignatureException, NoLongerValidCertificateException ;
	boolean solvedChallenge(X509Certificate certificate,byte[] solvedChallenge)throws RemoteException, CantVerifyChallengeException;
	void setDebugMode(int b) throws RemoteException;}
