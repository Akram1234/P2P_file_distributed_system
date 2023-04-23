import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.*;
import java.rmi.server.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;




public class MasterQuery extends UnicastRemoteObject implements Master
{
    // lookup : Filename -> List of peers containing that file
    private static Map<String, Set<String>> lookup;
    // peers : Stores all the registered peers
    private Set<String> peers;
    // bin : to store what all files are deleted
    private Map<String, Boolean> isDeleted;
    // Permissions Hashmap to manage all the permissions related to a file
    private Map<String, Permissions> permissions;
    // Hashmap to manage encryption keys for each file
    private static Map<String, SecretKey> secretKeys;
    // Hashmap to store RSA public and private keys for each user
    private static Map<String, PublicKey> peerRSAPublicKey;
    // Replication Factor fetched from property file
    private Integer replicaFactor;

    // Default constructor to throw RemoteException
    // from its parent constructor
    MasterQuery() throws IOException {
        super();
        lookup = new HashMap<>();
        peers = new HashSet<>();
        isDeleted = new HashMap<>();
        permissions = new HashMap<>();
        secretKeys = new HashMap<>();
        Properties prop = new Properties();
        peerRSAPublicKey = new HashMap<>();
//        prop.load(new FileInputStream("../resources/config.properties"));
        //Reading each property value
        //this.replicaFactor = Integer.parseInt(prop.getProperty("REPLICA_FACTOR"));
        this.replicaFactor = 3;
    }


    //Scheduler for malware check
    private final static ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

    @Override
    public Map.Entry<String, String> read(String fileName, String uri) throws RemoteException {
        try{
            String message;
            if(!hasFile(fileName)) {
                message = fileName + " doesn't exist";
                return new AbstractMap.SimpleEntry<>(message, null);
            }

            Permissions permissionObj = permissions.get(fileName);
            if(!permissionObj.canRead(uri)){
                message = "The peer doesn't have permission to read";
                return new AbstractMap.SimpleEntry<>(message, null);
            }

            List<String> paths = getPaths(fileName);
            String peerPath = paths.get(0);
            String key = Base64.getEncoder().encodeToString(secretKeys.get(fileName).getEncoded());
            key = RSA.encrypt(key, peerRSAPublicKey.get(uri));
            return new AbstractMap.SimpleEntry<>(peerPath, key);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;
    }

    @Override
    public boolean updatePublicKey(String uri, PublicKey publicKey)throws RemoteException {
        try{
            if(peerRSAPublicKey.containsKey(uri)){
                System.out.println("Successfully updated the RSA public key");
            } else {
                System.out.println("Successfully recieved peer RSA public key");
            }
            peerRSAPublicKey.put(uri, publicKey);
            return true;
        }catch (Exception e){
            System.out.println(e);
            return false;
        }
    }

    @Override
    public Map.Entry<Set<String>, String> create(String fileName, String uri) throws RemoteException {
        try {
            if (hasFile(fileName)){
               System.out.println(fileName + " already exist");
               return null;
            }
            Set<String> peersURI = getPaths_RF();
            Permissions permissionObj = new PermissionsImpl(fileName, uri);
            permissions.put(fileName, permissionObj);
            lookup.put(fileName, peersURI);
            isDeleted.put(fileName, false);
            secretKeys.put(fileName, AES.getSecretKey());
            String key = Base64.getEncoder().encodeToString(secretKeys.get(fileName).getEncoded());
            key = RSA.encrypt(key, peerRSAPublicKey.get(uri));
            System.out.println(fileName + " data updated in the lookup table");
            return new AbstractMap.SimpleEntry<>(peersURI, key);
        } catch (Exception io){
            io.printStackTrace();
        }
        return null;
    }

    @Override
    public String delegatePermission(String fileName, String uri, String otherURI, String permission) throws RemoteException {
        try{
            String message;
            if(!hasFile(fileName)) {
                message = fileName + " doesn't exit";
                return message;
            }
            Permissions permissionObj = permissions.get(fileName);
            if(permission.equals("read")){
                if(permissionObj.canRead(uri)){
                    if(permissionObj.canRead(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setRead(otherURI);
                    }
                } else {
                    message = "The peer doesn't have " + permission + " permission";
                    return message;
                }
            }
            if(permission.equals("write")){
                if(permissionObj.canWrite(uri)){
                    if(permissionObj.canWrite(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setWrite(otherURI);
                    }
                } else {
                    message = "The peer doesn't have " + permission + " permission";
                    return message;
                }
            }
            if(permission.equals("delete")){
                if(permissionObj.canDelete(uri)){
                    if(permissionObj.canDelete(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setWrite(otherURI);
                    }
                } else {
                    message = "The peer doesn't have " + permission + " permission";
                    return message;
                }
            }

        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;
    }

    @Override
    public String delete(String fileName, String uri) throws RemoteException {
        try{
            String message;
            if(!hasFile(fileName)) {
                message = fileName + " doesn't exit";
                return message;
            }
            Permissions permissionObj = permissions.get(fileName);
            if(!permissionObj.canDelete(uri)){
                message = "The peer doesn't have permission to delete/restore";
                return message;
            }
            List<String> paths = getPaths(fileName);
            String peerURI = paths.get(0);
            isDeleted.put(fileName, true);
            return peerURI;
        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;

    }

    @Override
    public Map.Entry<Map.Entry<String, String>, Set<String>> update(String fileName, String uri) throws RemoteException {
        try{
            Map.Entry<Map.Entry<String, String>, Set<String>> response;
            String message = "";
            if(!hasFile(fileName)) {
                message = fileName + " doesn't exist";
                return new AbstractMap.SimpleEntry<>(
                        new AbstractMap.SimpleEntry<>(message, null),
                        null);
            }

            Permissions permissionObj = permissions.get(fileName);
            if(!permissionObj.canWrite(uri)){
                message = "The peer doesn't have permission to write";
                return new AbstractMap.SimpleEntry<>(
                        new AbstractMap.SimpleEntry<>(message, null),
                        null);
            }
            String key = Base64.getEncoder().encodeToString(secretKeys.get(fileName).getEncoded());
            key = RSA.encrypt(key, peerRSAPublicKey.get(uri));
            Set<String> paths = new HashSet<>(getPaths(fileName));
            return new AbstractMap.SimpleEntry<>(
                    new AbstractMap.SimpleEntry<>(message, key),
                    paths);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;

    }

//    @Override
//    public Map.Entry<Map.Entry<String, SecretKey>, Set<String>> write(String fileName, String uri) throws RemoteException {
//        try{
//            Map.Entry<Map.Entry<String, SecretKey>, Set<String>> response;
//            String message = "";
//            if(!hasFile(fileName)) {
//                message = fileName + " doesn't exist";
//                return new AbstractMap.SimpleEntry<>(
//                        new AbstractMap.SimpleEntry<>(message, null),
//                        null);
//            }
//
//            Permissions permissionObj = permissions.get(fileName);
//            if(!permissionObj.canWrite(uri)){
//                message = "The peer doesn't have permission to write";
//                return new AbstractMap.SimpleEntry<>(
//                        new AbstractMap.SimpleEntry<>(message, null),
//                        null);
//            }
//            SecretKey key = secretKeys.get(fileName);
//            Set<String> paths = new HashSet<>(getPaths(fileName));
//            return new AbstractMap.SimpleEntry<>(
//                    new AbstractMap.SimpleEntry<>(message, key),
//                    paths);
//        }
//        catch(Exception e){
//            System.out.println(e);
//        }
//        return null;
//
//    }

    @Override
    public String restore(String fileName, String uri) throws RemoteException {
        try{
            String message;
            if(hasFile(fileName)) {
                message = fileName + " already exist";
                return message;
            }

            Permissions permissionObj = permissions.get(fileName);
            if(!permissionObj.canWrite(uri)){
                message = "The peer doesn't have permission to delete/restore";
                return message;
            }

            List<String> paths = new ArrayList<>(lookup.get(fileName));
            String peerPath = paths.get(0);
            isDeleted.put(fileName, false);
            return peerPath;
        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;

    }


    @Override
    public boolean hasFile(String filename) throws RemoteException{
        try {
            if(lookup.containsKey(filename) && !isDeleted.get(filename)){
                System.out.println("Lookup Successfull \n" +
                        "Master has "+ filename);
                return true;
            }
        } catch (Exception io){
            io.printStackTrace();
        }
        return false;
    }

    @Override
    public String getPath() throws IOException{
        try {
            int size = peers.size();
            int item = new Random().nextInt(size);
            int i = 0;
            for(String peer : peers)
            {
                if (i == item)
                    return peer;
                i++;
            }
        } catch (Exception io) {
            io.printStackTrace();
        }
        return null;
    }

    public Set<Integer> getRandomNumbers(int replicaFactor, int size){
        try{
            Set<Integer> nums = new HashSet<>();
            for(int i=0;i<replicaFactor;i++){
                int num = new Random().nextInt(size);
                while(!nums.contains(num)){
                    num = new Random().nextInt(size);
                }
                nums.add(num);
            }
            return nums;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public Set<String> getPaths_RF(){
        try {
            int size = peers.size();
            if(size<=this.replicaFactor){
                return peers;
            }
            Set<Integer> randomIntegers = getRandomNumbers(this.replicaFactor, size);
            Set<String> newPeers = new HashSet<>();
            for(int randomIndex : randomIntegers){
                int i = 0;
                for(String peer : peers){
                    if(i==randomIndex){
                        newPeers.add(peer);
                    }
                    i++;
                }
            }
            return newPeers;
        } catch (Exception io) {
            io.printStackTrace();
        }
        return null;
    }

    @Override
    public List<String> getPaths(String filename) throws RemoteException{
        try {
            if(hasFile(filename)){
                Set<String> setOfPaths = lookup.get(filename);
                List<String> paths = new ArrayList<>(setOfPaths);
                return paths;
            }
        } catch (Exception io){
            io.printStackTrace();
        }
        return null;
    }

    @Override
    public int registerPeer(String peerData) throws IOException{
        try {
            if(peerData!=null && peerData!="") {
                if(!peers.contains(peerData)){
                    peers.add(peerData);
                    return 1;
                } else {
                    return 0;
                }

            }
        } catch (Exception io){
            io.printStackTrace();
        }
        return -1;
    }


    public static boolean maliciousCheck() throws IOException {
        executorService.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                try {
                    for(String fileName : lookup.keySet()){
                        for(String peerPath : lookup.get(fileName)){
                            // connect with server
                            FDS peerServer =
                                    (FDS)Naming.lookup(peerPath);
                            String fileData = peerServer.read(AES.encrypt(fileName, secretKeys.get(fileName)));
                            if(fileData==null){
                                System.out.println("Malicious activity detected in the Master Server......");
                                System.out.println("Exiting......");
                                System.exit(1);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 5, TimeUnit.SECONDS);
        return true;
    }


}