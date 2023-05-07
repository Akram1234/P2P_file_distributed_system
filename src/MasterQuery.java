import javax.crypto.SecretKey;
import java.io.IOException;
import java.rmi.*;
import java.rmi.server.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class MasterQuery extends UnicastRemoteObject implements Master
{
    // lookup : Filename -> List of peers containing that file
    private static Map<String, Set<String>> table;
    // peers : Stores all the registered peers
    private Set<String> allPeers;
    // bin : to store what all files are deleted
    private Map<String, Boolean> deletedFiles;
    // FilePermissons Hashmap to manage all the permissions related to a file
    private Map<String, FilePermissons> filePermission;
    // Hashmap to manage encryption keys for each file
    private static Map<String, SecretKey> keys;
    // Hashmap to store RSAEncryption public and private keys for each user
    private static Map<String, PublicKey> peerRSAPublicKey;
    // Replication Factor fetched from property file
    private Integer replicaFactor;

    // Default constructor to throw RemoteException
    // from its parent constructor
    MasterQuery() throws IOException {
        super();
        table = new HashMap<>();
        allPeers = new HashSet<>();
        deletedFiles = new HashMap<>();
        filePermission = new HashMap<>();
        keys = new HashMap<>();
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

            FilePermissons permissionObj = filePermission.get(fileName);
            if(!permissionObj.canReadPermission(uri)){
                message = "The peer doesn't have permission to read";
                return new AbstractMap.SimpleEntry<>(message, null);
            }

            List<String> paths = getPaths(fileName);
            String peerPath = paths.get(0);
            String key = Base64.getEncoder().encodeToString(keys.get(fileName).getEncoded());
            key = RSAEncryption.encrypt(key, peerRSAPublicKey.get(uri));
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
                System.out.println("Successfully updated the RSAEncryption public key");
            } else {
                System.out.println("Successfully recieved peer RSAEncryption public key");
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
            FilePermissons permissionObj = new FilePermissionsImpl(fileName, uri);
            filePermission.put(fileName, permissionObj);
            table.put(fileName, peersURI);
            deletedFiles.put(fileName, false);
            keys.put(fileName, AESEncryption.getSecret());
            String key = Base64.getEncoder().encodeToString(keys.get(fileName).getEncoded());
            key = RSAEncryption.encrypt(key, peerRSAPublicKey.get(uri));
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
            FilePermissons permissionObj = filePermission.get(fileName);
            if(permission.equals("read")){
                if(permissionObj.canReadPermission(uri)){
                    if(permissionObj.canReadPermission(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setReadPermissions(otherURI);
                    }
                } else {
                    message = "The peer doesn't have " + permission + " permission";
                    return message;
                }
            }
            if(permission.equals("write")){
                if(permissionObj.canWritePermission(uri)){
                    if(permissionObj.canWritePermission(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setWritePermissions(otherURI);
                    }
                } else {
                    message = "The peer doesn't have " + permission + " permission";
                    return message;
                }
            }
            if(permission.equals("delete")){
                if(permissionObj.canDeletePermission(uri)){
                    if(permissionObj.canDeletePermission(otherURI)){
                        message = "The other peer already have "+permission;
                        return message;
                    } else {
                        permissionObj.setWritePermissions(otherURI);
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
            FilePermissons permissionObj = filePermission.get(fileName);
            if(!permissionObj.canDeletePermission(uri)){
                message = "The peer doesn't have permission to delete/restore";
                return message;
            }
            List<String> paths = getPaths(fileName);
            String peerURI = paths.get(0);
            deletedFiles.put(fileName, true);
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

            FilePermissons permissionObj = filePermission.get(fileName);
            if(!permissionObj.canWritePermission(uri)){
                message = "The peer doesn't have permission to write";
                return new AbstractMap.SimpleEntry<>(
                        new AbstractMap.SimpleEntry<>(message, null),
                        null);
            }
            String key = Base64.getEncoder().encodeToString(keys.get(fileName).getEncoded());
            key = RSAEncryption.encrypt(key, peerRSAPublicKey.get(uri));
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
//            FilePermissons permissionObj = permissions.get(fileName);
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

            FilePermissons permissionObj = filePermission.get(fileName);
            if(!permissionObj.canWritePermission(uri)){
                message = "The peer doesn't have permission to delete/restore";
                return message;
            }

            List<String> paths = new ArrayList<>(table.get(fileName));
            String peerPath = paths.get(0);
            deletedFiles.put(fileName, false);
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
            if(table.containsKey(filename) && !deletedFiles.get(filename)){
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
            int size = allPeers.size();
            int item = new Random().nextInt(size);
            int i = 0;
            for(String peer : allPeers)
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
            int size = allPeers.size();
            if(size<=this.replicaFactor){
                return allPeers;
            }
            Set<Integer> randomIntegers = getRandomNumbers(this.replicaFactor, size);
            Set<String> newPeers = new HashSet<>();
            for(int randomIndex : randomIntegers){
                int i = 0;
                for(String peer : allPeers){
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
                Set<String> setOfPaths = table.get(filename);
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
                if(!allPeers.contains(peerData)){
                    allPeers.add(peerData);
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
                    for(String fileName : table.keySet()){
                        for(String peerPath : table.get(fileName)){
                            // connect with server
                            FileDistributedSystem peerServer =
                                    (FileDistributedSystem)Naming.lookup(peerPath);
                            String fileData = peerServer.readFile(AESEncryption.encrypt(fileName, keys.get(fileName)));
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


interface Master extends Remote{
    public boolean hasFile(String filename) throws RemoteException;
    public List<String> getPaths(String filename) throws RemoteException;
    public String getPath() throws IOException;
    public int registerPeer(String peerData) throws IOException;
    public Map.Entry<String, String> read(String fileName, String uri) throws RemoteException;
    public Map.Entry<Set<String>, String> create(String fileName, String uri) throws RemoteException;
    public String delete(String fileName, String uri) throws RemoteException;
    public Map.Entry<Map.Entry<String, String>, Set<String>> update(String fileName, String uri) throws RemoteException;
    public String restore(String fileName, String uri) throws RemoteException;
    public String delegatePermission(String fileName, String uri, String otherURI, String permission) throws RemoteException;
    public boolean updatePublicKey(String uri, PublicKey publicKey) throws RemoteException;
}


interface FilePermissons {

    public void setReadPermissions(String IP);
    public void setWritePermissions(String IP);
    public void setDeletePermissions(String IP);

    public boolean revokeReadPermission(String IP);
    public boolean revokeWritePermission(String IP);
    public boolean revokeDeletePermission(String IP);

    public boolean canReadPermission(String IP);
    public boolean canWritePermission(String IP);
    public boolean canDeletePermission(String IP);

}

class FilePermissionsImpl implements FilePermissons {
    public String file;
    public Set<String> readPermissions;
    public Set<String> writePermissions;
    public Set<String> deletePermissions;

    public FilePermissionsImpl(String filepath){
        this.file = filepath;
        this.readPermissions = new HashSet<>();
        this.writePermissions = new HashSet<>();
        this.deletePermissions = new HashSet<>();
    }

    public FilePermissionsImpl(String filePath, String uri){
        this(filePath);
        this.readPermissions.add(uri);
        this.writePermissions.add(uri);
        this.deletePermissions.add(uri);
    }

    @Override
    public boolean canReadPermission(String IP) {
        return readPermissions.contains(IP);
    }

    @Override
    public boolean canWritePermission(String IP) {
        return writePermissions.contains(IP);
    }

    @Override
    public boolean canDeletePermission(String IP) {
        return deletePermissions.contains(IP);
    }

    @Override
    public void setReadPermissions(String IP) { this.readPermissions.add(IP); }

    @Override
    public void setWritePermissions(String IP) { this.writePermissions.add(IP); }

    @Override
    public void setDeletePermissions(String IP) { this.deletePermissions.add(IP); }

    @Override
    public boolean revokeReadPermission(String IP) { return this.readPermissions.remove(IP);  }

    @Override
    public boolean revokeWritePermission(String IP) { return this.writePermissions.remove(IP); }

    @Override
    public boolean revokeDeletePermission(String IP) { return this.deletePermissions.remove(IP); }
}

