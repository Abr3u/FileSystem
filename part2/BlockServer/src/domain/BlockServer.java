package domain;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


public class BlockServer {

	private final static int SERVER_PORT = 8888;
	private static final String SERVICE = "BlockServerService";
	
	public BlockServer() throws RemoteException {
	}

	public static void main(String[] args) throws RemoteException, IllegalArgumentException, AlreadyBoundException {
		
		Impl impl = new Impl(SERVER_PORT);

		LocateRegistry.createRegistry(SERVER_PORT);
		System.out.println("RMI registry running on port " + SERVER_PORT);

		Registry registry = LocateRegistry.getRegistry("localhost", SERVER_PORT);

		registry.bind(SERVICE, impl);

		System.out.println("Server running");
	}

}
