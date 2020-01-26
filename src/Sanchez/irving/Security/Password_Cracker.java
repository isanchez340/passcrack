package Sanchez.irving.Security;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Password_Cracker {
	
	private static String[][] readF() throws FileNotFoundException, IOException { //used for reading usernames and hashes for random passwords
		String[][] Hashes = null;
		try(BufferedReader br = new BufferedReader(new FileReader("resources/Random.txt"))) {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();
		    int i = 0;
		    Hashes = new String[lenF()][2];
		    String[] parts = null;
		    parts = line.split("	");
		    Hashes[i][0] = parts[0];
        	Hashes[i][1] = parts[1];
        	i++;
		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		        if(line != null) {
		        	parts = line.split("	");
		        	Hashes[i][0] = parts[0];
		        	Hashes[i][1] = parts[1];
		        	i++;
		        }
		        	
		    }
		    String everything = sb.toString();
		}
		catch(FileNotFoundException e) {
			System.out.print("No File was found!");
			System.exit(0);
		}
		return Hashes;
	}
	
	private static String[][] readFP() throws FileNotFoundException, IOException { //used for reading username, hashes, and salt from file
		String[][] Hashes = null;													//for dictionary passwords
		try(BufferedReader br = new BufferedReader(new FileReader("resources/Dictionary.txt"))) {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();
		    int i = 0;
		    Hashes = new String[10][3];
		    
		    String[] parts = null;
		    parts = line.split("	");
		    Hashes[i][0] = parts[0];
        	Hashes[i][1] = parts[1];
        	Hashes[i][2] = parts[2];
        	i++;
		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		        if(line != null) {
		        	parts = line.split("	");
		        	Hashes[i][0] = parts[0];
		        	Hashes[i][1] = parts[1];
		        	Hashes[i][2] = parts[2];
		        	i++;
		        }
		        	
		    }
		    String everything = sb.toString();
		}
		catch(FileNotFoundException e) {
			System.out.print("No File was found!");
			System.exit(0);
		}
		return Hashes;
	}
	
	private static String[] getDic() throws IOException {  //gets dictionary files from file
		String[] Dictionary = null;
		try(BufferedReader br = new BufferedReader(new FileReader("resources/wordsEn.txt"))) {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();
		    line = line.replace("'", "");
		    int i = 1;
		    Dictionary = new String[lenF()];
		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		        if(line != null) {
		        	line = line.replace("'", "");
		        	Dictionary[i] = line;
		        	i++;
		        }
		        	
		    }
		    String everything = sb.toString();
		}
		catch(FileNotFoundException e) {
			System.out.print("No File was found!");
			System.exit(0);
		}
		return Dictionary;
	}
	
	private static int lenF() throws FileNotFoundException, IOException { //helps with file reading
		int len = 1;
		try(BufferedReader br = new BufferedReader(new FileReader("resources/wordsEn.txt"))) {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();
		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		        if(line != null) {
		        	len++;
		        }
		    }
		    String everything = sb.toString();
		}
		catch(FileNotFoundException e) {
			System.out.print("No File was found!");
			System.exit(0);
		}
		return len;
	}
	
	private static void print(Object Message) {//fast printing
		System.out.print(Message);
	}
	private static void println(Object Message) { //fast printing
		System.out.println(Message);
	}
	
	private static String BtoH(byte[] bytes) {
		String hex = "";
		for(int i = 0; i < bytes.length; ++i) {
			hex = hex + String.format("%02x", bytes[i]);
		}
		return hex;
	}

	private static byte[] SHA256(String raw) throws NoSuchAlgorithmException {
		MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");
		byte[] hash = SHA256.digest(raw.getBytes(StandardCharsets.UTF_8));
		return hash;
	}
	
	private static String SHA1(byte[] raw) throws NoSuchAlgorithmException {
		MessageDigest SHA1 = MessageDigest.getInstance("SHA-1");
		raw = SHA1.digest(BtoH(raw).getBytes(StandardCharsets.UTF_8));
		String hashed = BtoH(raw);
		return hashed;
	}
	
	private static void brute(String[][] Hashes) throws NoSuchAlgorithmException { //bruteforces random passwords
		String[] abc = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_".split(""); //array with all allowed characters
		abc[0] = "";
		String password = "";
		String hash = null;
		long startTime = System.nanoTime();
		long endTime = 0;
		for(int i = 0; i < abc.length; ++i) { //loop for length 6 password
			for(int k = abc.length - 1; k > -1; --k) { //loop for length 5 password
				for(int m = abc.length - 1; m > -1; --m) { //loop for length 4 password
					for(int n = abc.length - 1; n > -1; --n) { //loop for length 3 password
						for(int o = abc.length - 1; o > -1; --o) { //loop for length 2 password
							for(int p = abc.length - 1; p > -1 ; --p) { //loop for length 1 password
								password = abc[p] + abc[o] +  abc[n] + abc[m] + abc[k] + abc[i]; //combination of all letters
								hash = SHA1(SHA256(password)); //performs double hash
									for(int j = 0; j < Hashes.length; ++j) {
										if(hash.equals(Hashes[j][1])) { //checks if hash matches any in the Random file
											endTime = System.nanoTime();
											println("Username: " + Hashes[j][0]);
											Hashes[j][1] = "";
											println("Craked Password: " + password);
											println("Cracked in : " +  (endTime - startTime) / 1000000 + " milliseconds");
											startTime = System.nanoTime();
											println("");
									}
								}
							}
						}
					}		
				}		
			}
		}
	}
	
	private static void Dictionary(String[][] Hashes, String[] Dict) throws NoSuchAlgorithmException {
		String password = "";
		String hash = null;
		long startTime = System.nanoTime();
		long endTime = 0;
		for(int j = 0; j < Hashes.length; ++j) {
			for(int i = 1; i < Dict.length; i++) {
				password = Dict[i];
				hash = password + Hashes[j][1];
				hash = SHA1(SHA256(hash));
					if(hash.equals(Hashes[j][2])) {
						endTime = System.nanoTime();
						println("Username: " + Hashes[j][0]);
						Hashes[j][1] = "";
						println("Craked Password: " + password);
						println("Cracked in : " +  (endTime - startTime) / 1000000 + " milliseconds");
						startTime = System.nanoTime();
						println("");
						i = Dict.length;
					}
			}
		}
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		String[][] Hashes = readF();
		brute(Hashes);
		//String[][] Hashes = readFP();
		//String[] Dict = getDic();
		/*for(int i = 0 ; i < Hashes.length; ++i) {
			print(Hashes[i][0] + " ");
			print(Hashes[i][1] + " ");
			println(Hashes[i][2]);
		}*/
		//println(SHA1(SHA256("stitchedSW4SNada2g")));
		//Dictionary(Hashes, Dict);
		
		//for(int i = 0; i < Hashes.length; ++i)
			//System.out.println(Hashes[i][0] + "		" + Hashes[i][1]);
		
	}

}
