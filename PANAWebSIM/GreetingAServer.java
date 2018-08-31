import java.net.*;
import java.io.*;

public class GreetingAServer extends Thread {
   private ServerSocket serverSocket;
   
   public GreetingAServer(int port) throws IOException {
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

            out.writeUTF("Kindly Provide your Credentials");	
			String username=in.readUTF();
			//System.out.println(username);
			out.writeUTF("correct");
			String password=in.readUTF();
			out.writeUTF("done");
			
			if(username.equals("sachin") && password.equals("sharma")){
				out.writeUTF("true");
			}
			else{
				out.writeUTF("false");
			}
			
			
            
            server.close();
            
         }catch(SocketTimeoutException s) {
            System.out.println("Socket timed out!");
            break;
         }catch(IOException e) {
            e.printStackTrace();
            break;
         }
      }
   }
   
   public static void main(String [] args) {
      int port = Integer.parseInt(args[0]);
      try {
         Thread t = new GreetingAServer(port);
         t.start();
      }catch(IOException e) {
         e.printStackTrace();
      }
   }
}