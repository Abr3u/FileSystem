package domain;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Arrays;

import exceptions.BufferTooShortException;
import exceptions.CantVerifyContentException;
import exceptions.CantVerifyMACException;
import exceptions.CantVerifySignatureException;

public class BSClient {

	private static Library library;
	private static String USAGE="Please pass one argument which is the number of bizantine servers you wish to tolerate";

	
	public static void main(String args[]) throws Exception {

		if(args.length!=1){
			System.out.println(USAGE);
			System.exit(-1);
		}
		int bizantines = Integer.parseInt(args[0]);
		int replicas = 3*bizantines +1;
		library = new Library(replicas,0);
		
//		testPosition0Size2000(); //normal
//		testReadAfterEOF();
//		testPosition2048Size3000(); //split content
//		testPosition6000Size500(); //padding after end of file
//		testPosition500Size2000(); //overwrite without EOF split blocks
//		testReadShortBuffer(); //not sure if needed
		//testSignature();//debugMode == 1 na library, tem de ser corrido o 1o teste antes
		
		//testPerfectLinks(replicas);//comentar library constructor
		
		//correr teste com server em debugMode == 2, library == 0
		//testRegularRegistryACKS();
		
		//correr teste com server em debugMode == 1, library == 0
		testRegularRegistryBadResponse();
		/*
		 * To run this test the server needs to be rebooted in debug mode.
		 * For this change the boolean in line 19 in BlockServer.java to true.
		 * The other tests also need to be commented out since they are expecting the system 
		 * to function normally.
		 * testContentIntegrity();
		 */
		
		
		System.out.println("FIM");
		}


	private static void testReadShortBuffer() throws CantVerifyContentException {
		System.out.println("testReadShortBuffer");
		byte[] expected = new byte[3000];
		try {
			library.FS_read(library.getId(), 0, 4000, expected);
			System.out.println("Failed test, didnt throw BufferTooShortException");
		}catch (BufferTooShortException e) {
			System.out.println("Passed Test, buffer too short");
		} catch (CantVerifySignatureException e) {
			System.out.println("Test Failed, couldn't verify signature");
		} catch (CantVerifyMACException e) {
			System.out.println("Test Failed, couldn't verify hash");
		}
	}
//
//	private static void testContentIntegrity() throws BufferTooShortException {
//		System.out.println("testContentIntegrity");
//		library = new Library(true);
//		byte[] buffer = new byte[2048];
//		try {
//			library.FS_read(library.getId(), 0, 2048, buffer);
//			System.out.println("Failed Test, didnt throw CantVerifyContentException");	
//		} catch (CantVerifyContentException e) {
//			System.out.println("Passed Test, couldnt verify Integrity");
//		} catch (CantVerifySignatureException e) {
//			System.out.println("Passed Failed, couldnt verify Signature");
//		}	
//	}
//
	private static void testSignature() {
		System.out.println("testSignature");
		byte[] content = new byte[2048];
		Arrays.fill(content, (byte) 7);
		try {
			library.FS_write(0, 2000, content);
			System.out.println("Failed Test, didnt throw CantVerifyContentException");
		} catch (CantVerifySignatureException e) {
			System.out.println("Passed Test, couldnt verify Signature");
		} catch (CantVerifyMACException e) {
			System.out.println("Failed Test, threw cant verify MAC");
		}	
	}

	private static void testRegularRegistryACKS() {
		System.out.println("testRegularRegistryACK");
		byte[] content = new byte[2048];
		Arrays.fill(content, (byte) 7);
		try {
			library.FS_write(0, 2000, content);
			System.out.println("received enough ACKS");
		} catch (CantVerifySignatureException e) {
			System.out.println("Failed Test, threw cant verify Signature");
		} catch (CantVerifyMACException e) {
			System.out.println("Failed Test, threw cant verify Hash");
		}	
	}
	
	private static void testRegularRegistryBadResponse() {
		System.out.println("testRegularRegistryBADResponses");
		byte[] content = new byte[2048];
		Arrays.fill(content, (byte) 7);
		try {
			library.FS_write(0, 2000, content);
			System.out.println("received enough ACKS with good responses");
		} catch (CantVerifySignatureException e) {
			System.out.println("Failed Test, threw cant verify Signature");
		} catch (CantVerifyMACException e) {
			System.out.println("Failed Test, threw cant verify Hash");
		}	
	}
	
	private static void testPerfectLinks(int replicas) {
		try {
			library = new Library(replicas,2);
			System.out.println("Failed Test");
		} catch (CantVerifyMACException e) {
			System.out.println("Passed Test, threw CantVerifyMAC");
		}
	}
	
	private static void testReadAfterEOF() {
		System.out.println("testReadAfterEOF");
		byte[] buffer = new byte[3000];
		try {
			library.FS_read(library.getId(), 0, 3000, buffer);
		} catch (CantVerifyContentException | BufferTooShortException e) {
			System.out.println("Failed Test, threw an Exception");
			e.printStackTrace();
		} catch (CantVerifySignatureException e) {
			System.out.println("Failed Test, threw an Exception");
			e.printStackTrace();
		} catch (CantVerifyMACException e) {
			System.out.println("Test Failed, threw an Exception");
		}
		System.out.println("Passed Test");
	}
//
	private static void testReadSimple() {
		byte[] buffer = new byte[2000];
		try {
			library.FS_read(library.getId(), 0, 2000, buffer);
		} catch (CantVerifyContentException | BufferTooShortException e) {
			System.out.println("Failed Test, threw an Exception");
			e.printStackTrace();
		} catch (CantVerifySignatureException e) {
			System.out.println("Failed Test, threw an Exception");
			e.printStackTrace();
		}
		 catch (CantVerifyMACException e) {
				System.out.println("Test Failed, couldn't verify hash");
		}
		System.out.println("Passed Test");
	}

	private static void testPosition500Size2000() throws CantVerifySignatureException, CantVerifyMACException {
		System.out.println("testPosition500Size2000");
		byte[] b2000 = new byte[2000];
		byte[] returned = new byte[2500];
		byte[] expected = new byte[2500];
		Arrays.fill(b2000, (byte) 5);
		Arrays.fill(expected, 0, 500, (byte)7);
		Arrays.fill(expected, 500, 2500, (byte)5);
		library.FS_write(500, 2000, b2000);
		
		try {
			library.FS_read(library.getId(), 0, 2500, returned);
		} catch (CantVerifyContentException e) {
			System.out.println("Failed Test, cant verify content");
		} catch (BufferTooShortException e) {
			System.out.println("never comes here");
		} catch (CantVerifyMACException e) {
			System.out.println("Test Failed, couldn't verify hash");
		}
		
		if(Arrays.equals(expected, returned)){
			System.out.println("Passed Test");
		}else{
			System.out.println("Failed Test Equals");
		}
	}

	private static void testPosition6000Size500() throws CantVerifySignatureException, BufferTooShortException, CantVerifyMACException {
		System.out.println("testPosition6000Size500");
		byte[] b500 = new byte[500];
		byte[] returned = new byte[2000];
		byte[] expected = new byte[2000];
		Arrays.fill(expected, 0, 500, (byte)0);
		Arrays.fill(expected, 500, 1000, (byte)7);
		Arrays.fill(expected, 1000, 2000, (byte)0);
		Arrays.fill(b500, (byte) 7);
		library.FS_write(6000, 500, b500);
		try {
			library.FS_read(library.getId(), 5500, 2000, returned);
		} catch (CantVerifyContentException e) {
			System.out.println("Failed Test Verify");
			}
		 catch (CantVerifyMACException e) {
				System.out.println("Test Failed, couldn't verify hash");
			}
		if(Arrays.equals(expected, returned)){
			System.out.println("Passed Test");
		}else{
			System.out.println("Failed Test Equals");
		}
		
	}

	private static void testPosition2048Size3000() throws CantVerifySignatureException, BufferTooShortException, CantVerifyMACException {
		System.out.println("testPosition2048Size3000");
		byte[] b3000 = new byte[3000];
		byte[] returned = new byte[3000];
		Arrays.fill(b3000, (byte) 7);
		library.FS_write(2048, 3000, b3000);
		try {
			library.FS_read(library.getId(), 2048, 3000, returned);
		} catch (CantVerifyContentException e) {
			System.out.println("Failed Test Verify");
		} catch (CantVerifyMACException e) {
			System.out.println("Test Failed, couldn't verify hash");
		}
		if(Arrays.equals(b3000, returned)){
			System.out.println("Passed Test");
		}else{
			System.out.println("Failed Test Equals");
		}
	}

	private static void testPosition0Size2000() throws CantVerifySignatureException, BufferTooShortException, CantVerifyMACException {
		System.out.println("testPosition0Size2000");
		byte[] b2000 = new byte[2000];
		byte[] returned = new byte[2000];
		Arrays.fill(b2000, (byte) 7);
		library.FS_write(0, 2000, b2000);
		try {
			library.FS_read(library.getId(), 0, 2000, returned);
		} catch (CantVerifyContentException e) {
			System.out.println("Failed Test Verify");
		} catch (CantVerifyMACException e) {
			System.out.println("Test Failed, couldn't verify hash");
		}
		if(Arrays.equals(b2000, returned)){
			System.out.println("Passed Test");
		}else{
			System.out.println("Failed Test Equals");
		}
	}
}