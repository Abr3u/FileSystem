package domain;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Arrays;

import exceptions.CantVerifyMACException;

public class ClientService extends UnicastRemoteObject implements ClientInterface {

	private Library _library;

	public ClientService(Library l) throws RemoteException {
		_library = l;
	}

	@Override
	public void receiveAck(int ts, byte[] hash) throws RemoteException {

		if (ts == _library.getLastWTS()) {

			byte[] wtsB = ByteBuffer.allocate(4).putInt(ts).array();
			byte[] expected = _library.getExpectedChallenge();
			byte[] toHash = new byte[wtsB.length+expected.length];
			System.arraycopy(wtsB, 0, toHash, 0, wtsB.length);
			System.arraycopy(expected, 0, toHash, wtsB.length, expected.length);
			byte[] hashExpected = _library.getMAC(toHash);

			if (!Arrays.equals(hashExpected, hash)) {
				return;
			}

			_library.incrementAcks();
		}
	}
	
	@Override
	public void receiveAckH(int ts, byte[] hash) throws RemoteException {

		if (ts == _library.getLastWTS()) {

			byte[] wtsB = ByteBuffer.allocate(4).putInt(ts).array();
			byte[] expected = _library.getExpectedChallenge();
			byte[] toHash = new byte[wtsB.length+expected.length];
			System.arraycopy(wtsB, 0, toHash, 0, wtsB.length);
			System.arraycopy(expected, 0, toHash, wtsB.length, expected.length);
			byte[] hashExpected = _library.getMAC(toHash);

			if (!Arrays.equals(hashExpected, hash)) {
				return;
			}

			_library.incrementAcksH();
		}
	}

	@Override
	public void receivePKBlock(int r, byte[] content, int ts, byte[] hash) throws RemoteException {

		if (r == _library.getLastRid()) {

			byte[] wtsB = ByteBuffer.allocate(4).putInt(ts).array();
			byte[] ridB = ByteBuffer.allocate(4).putInt(r).array();
			byte[] expected = _library.getExpectedChallenge();
			byte[] toHash = new byte[ridB.length + content.length + wtsB.length+expected.length];
			System.arraycopy(ridB, 0, toHash, 0, ridB.length);
			System.arraycopy(content, 0, toHash, ridB.length, content.length);
			System.arraycopy(wtsB, 0, toHash, ridB.length + content.length, wtsB.length);
			System.arraycopy(expected, 0, toHash, ridB.length + content.length+wtsB.length, expected.length);
			byte[] hashExpected = _library.getMAC(toHash);

			if (!Arrays.equals(hashExpected, hash)) {
				return;
			}

			_library.addRead(ts, content);
		}
	}

	@Override
	public void receiveContentBlock(int r, byte[] content, int ts, byte[] hash) throws RemoteException {

		if (content != null) {
			if (r == _library.getLastRid()) {

				byte[] ridB = ByteBuffer.allocate(4).putInt(r).array();
				byte[] wtsB = ByteBuffer.allocate(4).putInt(ts).array();
				byte[] expected = _library.getExpectedChallenge();
				byte[] toHash = new byte[ridB.length + content.length + wtsB.length+expected.length];
				System.arraycopy(ridB, 0, toHash, 0, ridB.length);
				System.arraycopy(content, 0, toHash, ridB.length, content.length);
				System.arraycopy(wtsB, 0, toHash, ridB.length + content.length, wtsB.length);
				System.arraycopy(expected, 0, toHash, ridB.length + content.length+wtsB.length, expected.length);
				byte[] hashExpected = _library.getMAC(toHash);

				if (!Arrays.equals(hash, hashExpected)) {
					return;
				}
				_library.addRead(ts, content);
				if (_library.checkContentBlockIntegrity(content)) {
					_library.setEnoughReads(true);
				}
			}
		}
	}

}
