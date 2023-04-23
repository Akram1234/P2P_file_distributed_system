import java.io.IOException;
import java.rmi.*;
import java.util.List;

public interface FDS extends Remote {
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