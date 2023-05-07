import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Server {
    public String masterPort;
    public String masterIP;
    public String myPort;
    public String myIP;
    public String propFilePath;

    Server(String propFilePath) throws IOException {
        this.propFilePath = propFilePath;
        Properties prop = new Properties();
        prop.load(new FileInputStream(propFilePath));

        //Reading each property value
        masterPort = prop.getProperty("MASTER_PORT");
        masterIP = prop.getProperty("MASTER_IP");
        myPort = prop.getProperty("SERVER_PORT");
        myIP = prop.getProperty("SERVER_IP");

    }

    Server(int peerServerId, String propFilePath) throws IOException {
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
            CentralServer masterAccess =
                    (CentralServer)Naming.lookup("rmi://"+masterIP+":"+masterPort+"/master");
            int response = masterAccess.registerPeer("rmi://"+myIP+":"+myPort+"/peer");

            // registers the user in CentralServer server
            if(response == 1){
                System.out.println("Peer Server Registered Successfully");
            }else if(response == 0){
                System.out.println("Peer Server Already Registered");
            } else {
                System.out.println("Peer Server Couldn't be registered");
            }

            // Create an object of the interface
            // implementation class
            FileDistributedSystem obj = new FileDistributedSystemImpl(this.propFilePath);

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
        new Server("../resources/config.properties").run();
    }
}
