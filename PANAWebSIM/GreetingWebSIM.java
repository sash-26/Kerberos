import java.net.*;
import java.io.*;
import java.util.Scanner;
public class GreetingWebSIM extends Thread {
   private ServerSocket serverSocket;
   
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

            System.out.println("Do You Want To Validate The User (yes/no)");
			Scanner scanner = new Scanner(System.in);
			String s;
			while(true){
				s=scanner.next();
				System.out.println(s);
				if(s.equals("yes")){
					out.writeUTF("continue");
					//server.close();
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
}