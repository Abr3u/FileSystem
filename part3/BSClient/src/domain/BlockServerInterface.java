package domain;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.PublicKey;

import exceptions.CantFindFileException;
import exceptions.CantVerifyMACException;
import exceptions.CantVerifySignatureException;

public interface BlockServerInterface extends Remote{
	
	void get(byte[] id, int rid, byte[] hash,byte[] challenge) throws RemoteException,CantVerifyMACException;
	void put_k(byte[] data, byte[] signature, java.security.PublicKey public_key , int wts, byte[] hash,byte[] challenge) throws RemoteException,CantVerifyMACException, CantFindFileException, CantVerifySignatureException;
	void put_h(byte[] data, int wts, byte[] hash,byte[] challenge) throws RemoteException,CantVerifyMACException, CantFindFileException;
	}
