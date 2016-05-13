package domain;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ClientInterface extends Remote{
	void receiveAck(int ts, byte[] hash) throws RemoteException;
	void receiveAckH(int ts, byte[] hash) throws RemoteException;
	void receivePKBlock(int r, byte[] content, int ts, byte[] hash) throws RemoteException;
	void receiveContentBlock(int r, byte[] content, int ts, byte[] hash) throws RemoteException;
}