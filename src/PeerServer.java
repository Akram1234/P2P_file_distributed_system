import java.io.FileNotFoundException;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class PeerServer {
    public String masterPort;
    public String masterIP;
    public String myPort;
    public String myIP;
    public String propFilePath;

    PeerServer(String propFilePath) throws IOException {
        this.propFilePath = propFilePath;
        Properties prop = new Properties();
        prop.load(new FileInputStream(propFilePath));

        //Reading each property value
        masterPort = prop.getProperty("MASTER_PORT");
        masterIP = prop.getProperty("MASTER_IP");
        myPort = prop.getProperty("SERVER_PORT");
        myIP = prop.getProperty("SERVER_IP");

    }

    PeerServer(int peerServerId, String propFilePath) throws IOException {
        this.propFilePath = propFilePath;
        Properties prop = new Properties();
        prop.load(new FileInputStream(this.propFilePath));

        masterPort = prop.getProperty("MASTER_PORT");
        masterIP = prop.getProperty("MASTER_IP");
        myPort = prop.getProperty("SERVER_PORT_"+peerServerId);
        myIP = prop.getProperty("SERVER_IP_"+peerServerId);
    }

    public void run(){
        try
        {
            System.out.println("Peer Server started");
            Master masterAccess =
                    (Master)Naming.lookup("rmi://"+masterIP+":"+masterPort+"/master");
            System.out.println("asds");
            int response = masterAccess.registerPeer("rmi://"+myIP+":"+myPort+"/peer");

            // registers the user in Master server
            if(response == 1){
                System.out.println("Peer Server Registered Successfully");
            }else if(response == 0){
                System.out.println("Peer Server Already Registered");
            } else {
                System.out.println("Peer Server Couldn't be registered");
            }

            // Create an object of the interface
            // implementation class
            FDS obj = new FDSQuery(this.propFilePath);

            // rmiregistry within the server JVM with
            System.out.println("port:"+myPort);
            LocateRegistry.createRegistry(Integer.parseInt(myPort));

            // Binds the remote object by the name
            Naming.rebind("rmi://"+myIP+":"+myPort+"/peer",obj);
        }
        catch(Exception ae)
        {
            ae.printStackTrace();
        }
    }
    public static void main(String args[]) throws IOException {
        new PeerServer("../resources/config.properties").run();
    }
}
