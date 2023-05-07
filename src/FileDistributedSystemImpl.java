import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.rmi.*;
import java.rmi.server.*;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

interface FileDistributedSystem extends Remote {
    // Declaring the method prototype
    public String readFile(String filename) throws Exception;
    public String createFile(String filename, String data) throws Exception;
    public String createDirectory(String directoryname) throws Exception;
    public String updateFile(String filename, String data) throws Exception;
    public String writeFile(String filename, String data) throws Exception;
    public boolean restoreFile(String filename) throws Exception;
    public boolean deleteFile(String filename) throws Exception;
}

public class FileDistributedSystemImpl extends UnicastRemoteObject implements FileDistributedSystem
{
    public HashMap<String, Boolean> isDeleted;

    public int replicaFactor;

    // Default constructor to throw RemoteException
    // from its parent constructor
    FileDistributedSystemImpl(String propFilePath) throws IOException {
        super();
        isDeleted = new HashMap<>();
        Properties prop = new Properties();
        prop.load(new FileInputStream(propFilePath));
        this.replicaFactor = Integer.parseInt(prop.getProperty("REPLICA_FACTOR"));
    }

    @Override
    public boolean deleteFile(String file) throws Exception {
        FutureTask delete = new FutureTask<Boolean>(new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
                if(isDeleted.containsKey(file)){
                    isDeleted.put(file, true);
                    System.out.println("Successfully deleted - " + file);
                    return true;
                }
                return false;
            }
        });
        new Thread(delete).start();
        return (boolean) delete.get();
    }

    @Override
    public String writeFile(String filename, String fileData) throws Exception {
        FutureTask write = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    FileWriter myWriter = new FileWriter(filename);
                    myWriter.write(fileData);
                    myWriter.close();
                    System.out.println("Successfully wrote to the " + filename);
                    return filename;
                } catch (IOException io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(write).start();
        return (String) write.get();
    }

    @Override
    public boolean restoreFile(String file) throws Exception {
        FutureTask restore = new FutureTask<Boolean>(new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {

                if(isDeleted.containsKey(file)){
                    isDeleted.put(file, false);
                    System.out.println("Successfully restored - " + file);
                    return true;
                }
                return false;
            }
        });
        new Thread(restore).start();
        return (boolean) restore.get();
    }

    @Override
    public String createFile(String file, String fileData) throws Exception {
        FutureTask create = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    FileWriter myWriter = new FileWriter(file);
                    isDeleted.put(file, false);
                    myWriter.write(fileData);
                    myWriter.close();
                    System.out.println("Successfully created " + file);
                    return file;
                } catch (IOException io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(create).start();
        return (String) create.get();
    }

    @Override
    public String readFile(String file) throws Exception{
        FutureTask read = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {
                if(isDeleted.containsKey(file) && !isDeleted.get(file)){
                    try {
                        File f = new File(file);
                        if(f.isDirectory()) return "";
                        return Files.readString(Path.of(file));
                    } catch (IOException io){
                        io.printStackTrace();
                    }
                }
                return null;
            }
        });
        new Thread(read).start();
        return (String) read.get();
    }



    @Override
    public String createDirectory(String directory) throws Exception {
        FutureTask create = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    File dir = new File(directory);
                    isDeleted.put(directory, false);
                    //creates Directory
                    dir.mkdirs();
                    System.out.println("Successfully created " + directory);
                    return directory;
                } catch (Exception io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(create).start();
        return (String) create.get();
    }

    @Override
    public String updateFile(String file, String fileData) throws Exception {
        FutureTask update = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {
                if(isDeleted.containsKey(file) && !isDeleted.get(file)){
                    try {
                        Files.write(Paths.get(file), fileData.getBytes(), StandardOpenOption.APPEND);
                        return Files.readString(Path.of(file));
                    }catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        new Thread(update).start();
        return (String) update.get();

    }



}