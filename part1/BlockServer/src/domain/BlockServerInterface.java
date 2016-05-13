package domain;

import java.rmi.Remote;
import java.rmi.RemoteException;

import exceptions.CantFindFileException;
import exceptions.CantVerifySignatureException;

public interface BlockServerInterface extends Remote{
	
	//String init(String id) throws RemoteException, CantFindFileException;
	byte[] get(byte[] id) throws RemoteException;
	byte[] put_k(byte[] data, byte[] signature, java.security.PublicKey public_key/*, byte[] recover,int pos, int size*/) throws RemoteException, CantFindFileException, CantVerifySignatureException;
	byte[] put_h(byte[] data) throws RemoteException, CantFindFileException;
}
