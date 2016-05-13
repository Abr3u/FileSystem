package domain;

import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

public class BlockServer {

	private final static int SERVER_PORT = 8888;
	private static final String SERVICE = "BlockServerService";
	private static final String USAGE = "Please pass one argument which is the number of replicas to run";

	public BlockServer() throws RemoteException {
	}

	public static void main(String[] args) throws RemoteException, IllegalArgumentException, AlreadyBoundException {

		if (args.length != 1) {
			System.out.println(USAGE);
			System.exit(-1);
		}

		int i;
		int bizantines = Integer.parseInt(args[0]);
		int replicas = bizantines*3+1;
		for (i = 0; i < replicas; i++) {

			int replicaServerPort = SERVER_PORT + i;
			// 0 - no debugMode; 1 - bad responses; 2 - no response

			// test not enough acks
//			 Impl impl;
//			 if(i!=0){
//			 impl = new Impl(replicaServerPort, 0);
//			 }else{
//			 impl = new Impl(replicaServerPort, 2);
//			 }
			// test bad responses
			 Impl impl;
			 if (i != 0) {
			 impl = new Impl(replicaServerPort, 0);
			 } else {
			 impl = new Impl(replicaServerPort, 1);
			 }

			// normal mode
			//Impl impl = new Impl(replicaServerPort, 0);

			// RMIwithSSL(replicaServerPort,impl);

			LocateRegistry.createRegistry(replicaServerPort);
			System.out.println("RMI registry running on port " + replicaServerPort);

			Registry registry = LocateRegistry.getRegistry("localhost", replicaServerPort);

			registry.bind(SERVICE, impl);
		}
	}

	private static void RMIwithSSL(int replicaServerPort, Impl i) {
		System.setProperty("javax.net.ssl.keyStore",
				"C:\\Users\\Luc�lia\\Documents\\GitHub\\SecProject3\\BSServer\\src\\keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "banana");
		System.setProperty("javax.net.ssl.trustStore",
				"C:\\Users\\Luc�lia\\Documents\\GitHub\\SecProject3\\BSServer\\src\\truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "password");

		try {
			LocateRegistry.createRegistry(replicaServerPort, new SslRMIClientSocketFactory(),
					new SslRMIServerSocketFactory(null, null, true));

			Registry registry = LocateRegistry.getRegistry("192.168.1.69", replicaServerPort,
					new SslRMIClientSocketFactory());
			registry.bind(SERVICE, i);

		} catch (RemoteException | IllegalArgumentException | AlreadyBoundException e) {
			e.printStackTrace();
		}
		System.out.println("RMI registry running on port " + replicaServerPort);

	}
}
