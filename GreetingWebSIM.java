import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class GreetingWebSIM extends Thread {
   private ServerSocket serverSocket;
    String key = "E1BB465D57CAE7ACDBBE8091F9CE83DF";
 private static final String ALGORITMO = "AES/CBC/PKCS5Padding";
   private static final String CODIFICACION = "UTF-8";
   public GreetingWebSIM(int port) throws IOException {
      serverSocket = new ServerSocket(port);
      serverSocket.setSoTimeout(10000000);
   }

   public void run() {
      while(true) {
         try {
            System.out.println("Waiting for client on port " + 
               serverSocket.getLocalPort() + "...");
            Socket server = serverSocket.accept();
            
            System.out.println("Just connected to " + server.getRemoteSocketAddress());
            DataInputStream in = new DataInputStream(server.getInputStream());
            
            //System.out.println(in.readUTF());

            DataOutputStream out = new DataOutputStream(server.getOutputStream());
            /*out.writeUTF("Thank you for connecting to " + server.getLocalSocketAddress()
               + "\nGoodbye!");
             */
			 
			 String enc_u=in.readUTF();
			 String enc_nd=in.readUTF();
			 String enc_timestamp=in.readUTF();
			 String enc_randomnum=in.readUTF();
			 String user_name=decrypt(enc_u,key);
			 String nd=decrypt(enc_nd,key);
			 String timestamp=decrypt(enc_timestamp,key);
			 String randomnum=decrypt(enc_randomnum,key);
            System.out.println("Do You Want To Validate The User "+user_name+" with nd key "+nd+" and current time stamp "+timestamp+" and random number is "+randomnum+"  (yes/no)");
			Scanner scanner = new Scanner(System.in);
			String s;
			while(true){
				s=scanner.next();
				System.out.println(s);
				if(s.equals("yes")){
					
					//out.writeUTF("continue");
					//server.close();
					String tmp2="continue"+"//////////"+key+"//////////"+timestamp;
					String enc_tmp2=encrypt(tmp2,key);
					System.out.println(enc_tmp2);
					String fi_tmp="continue"+"//////////"+nd+"//////////"+key+"//////////"+timestamp+"//////////"+enc_tmp2;
					System.out.println(fi_tmp);
					String enc_final=encrypt(fi_tmp,key);
					out.writeUTF(enc_final);
					break;
				}
				else if(s.equals("no")){
					out.writeUTF("break");
			        //server.close();
					break;
				}
				else{
					System.out.println("Answer Only yes or no....no other words");
					continue;
				}
			}
            

            
         }catch(SocketTimeoutException s) {
            System.out.println("Socket timed out!");
            break;
         }catch(IOException e) {
            e.printStackTrace();
            break;
         }
		 catch(Exception e){
			 e.printStackTrace();
		 }
      }
   }
   
   public static void main(String [] args) {
      int port = Integer.parseInt(args[0]);
      try {
         Thread t = new GreetingWebSIM(port);
         t.start();
      }catch(IOException e) {
         e.printStackTrace();
      }
   }
   public static String decrypt(String encodedInitialData, String key)throws InvalidKeyException, IllegalBlockSizeException,BadPaddingException, UnsupportedEncodingException,NoSuchAlgorithmException, NoSuchPaddingException,InvalidAlgorithmParameterException{
	byte[] encryptedData = DatatypeConverter.parseBase64Binary(encodedInitialData);
	byte[] raw = DatatypeConverter.parseHexBinary(key);
	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	Cipher cipher = Cipher.getInstance(ALGORITMO);
	byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
	byte[] cipherText = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
	IvParameterSpec iv_specs = new IvParameterSpec(iv);
	cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv_specs);
	byte[] plainTextBytes = cipher.doFinal(cipherText);
	String plainText = new String(plainTextBytes);
	return plainText;
	}
	public static String encrypt(String plaintext, String key)throws NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeyException, IllegalBlockSizeException,BadPaddingException, IOException{
	byte[] raw = DatatypeConverter.parseHexBinary(key);
	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	Cipher cipher = Cipher.getInstance(ALGORITMO);
	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	byte[] cipherText = cipher.doFinal(plaintext.getBytes(CODIFICACION));
	byte[] iv = cipher.getIV();
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	outputStream.write(iv);
	outputStream.write(cipherText);
	byte[] finalData = outputStream.toByteArray();
	String encodedFinalData = DatatypeConverter.printBase64Binary(finalData);
	return encodedFinalData;
}
}