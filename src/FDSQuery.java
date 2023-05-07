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

interface FDS extends Remote {
    // Declaring the method prototype
    public String read(String filename) throws Exception;
    public String create(String filename, String data) throws Exception;
    public String createDirectory(String directoryname) throws Exception;
    public String update(String filename, String data) throws Exception;
    public String write(String filename, String data) throws Exception;
    public boolean restore(String filename) throws Exception;
    public List<String> getAllFiles(String path) throws RemoteException;
    public boolean delete(String filename) throws Exception;
}

public class FDSQuery extends UnicastRemoteObject implements FDS
{
    public HashMap<String, Boolean> isDeleted;

    public int replicaFactor;

    // Default constructor to throw RemoteException
    // from its parent constructor
    FDSQuery(String propFilePath) throws IOException {
        super();
        isDeleted = new HashMap<>();
        Properties prop = new Properties();
        prop.load(new FileInputStream(propFilePath));
        //Reading each property value
        this.replicaFactor = Integer.parseInt(prop.getProperty("REPLICA_FACTOR"));
    }


    @Override
    public String read(String filename) throws Exception{
        FutureTask readTask = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {
                if(isDeleted.containsKey(filename) && !isDeleted.get(filename)){
                    try {
                        File f = new File(filename);
                        if(f.isDirectory()) return "";
                        return Files.readString(Path.of(filename));
                    } catch (IOException io){
                        io.printStackTrace();
                    }
                }
                return null;
            }
        });
        new Thread(readTask).start();
        return (String) readTask.get();
    }

    @Override
    public String create(String filename, String data) throws Exception {
        FutureTask createTask = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    FileWriter myWriter = new FileWriter(filename);
                    isDeleted.put(filename, false);
                    myWriter.write(data);
                    myWriter.close();
                    System.out.println("Successfully created " + filename);
                    return filename;
                } catch (IOException io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(createTask).start();
        return (String) createTask.get();
    }

    @Override
    public String createDirectory(String directoryname) throws Exception {
        FutureTask createTask = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    File dir = new File(directoryname);
                    isDeleted.put(directoryname, false);
                    //creates Directory
                    dir.mkdirs();
                    System.out.println("Successfully created " + directoryname);
                    return directoryname;
                } catch (Exception io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(createTask).start();
        return (String) createTask.get();
    }

    @Override
    public String write(String filename, String data) throws Exception {
        FutureTask writeTask = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {

                try {
                    FileWriter myWriter = new FileWriter(filename);
                    myWriter.write(data);
                    myWriter.close();
                    System.out.println("Successfully wrote to the " + filename);
                    return filename;
                } catch (IOException io) {
                    io.printStackTrace();
                }

                return null;
            }
        });
        new Thread(writeTask).start();
        return (String) writeTask.get();
    }

    @Override
    public String update(String filename, String data) throws Exception {
        FutureTask updateTask = new FutureTask<String>(new Callable<String>() {
            @Override
            public String call() throws Exception {
                if(isDeleted.containsKey(filename) && !isDeleted.get(filename)){
                    try {
                        Files.write(Paths.get(filename), data.getBytes(), StandardOpenOption.APPEND);
                        return Files.readString(Path.of(filename));
                    }catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        new Thread(updateTask).start();
        return (String) updateTask.get();

    }

    @Override
    public boolean restore(String filename) throws Exception {
        FutureTask createTask = new FutureTask<Boolean>(new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {

                if(isDeleted.containsKey(filename)){
                    isDeleted.put(filename, false);
                    System.out.println("Successfully restored - " + filename);
                    return true;
                }
                return false;
            }
        });
        new Thread(createTask).start();
        return (boolean) createTask.get();
    }

    @Override
    public List<String> getAllFiles(String path) throws RemoteException {
        return null;
    }

    @Override
    public boolean delete(String filename) throws Exception {
        FutureTask deleteTask = new FutureTask<Boolean>(new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
                if(isDeleted.containsKey(filename)){
                    isDeleted.put(filename, true);
                    System.out.println("Successfully deleted - " + filename);
                    return true;
                }
                return false;
            }
        });
        new Thread(deleteTask).start();
        return (boolean) deleteTask.get();
    }
}