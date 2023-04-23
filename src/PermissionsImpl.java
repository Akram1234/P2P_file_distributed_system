import java.util.HashSet;
import java.util.Set;

public class PermissionsImpl implements Permissions {
    public String filePath;
    public Set<String> read;
    public Set<String> write;
    public Set<String> delete;

    public PermissionsImpl(String filepath){
        this.filePath = filepath;
        this.read = new HashSet<>();
        this.write = new HashSet<>();
        this.delete = new HashSet<>();
    }

    public PermissionsImpl(String filePath, String uri){
        this(filePath);
        this.read.add(uri);
        this.write.add(uri);
        this.delete.add(uri);
    }

    @Override
    public boolean canRead(String IP) {
        return read.contains(IP);
    }

    @Override
    public boolean canWrite(String IP) {
        return write.contains(IP);
    }

    @Override
    public boolean canDelete(String IP) {
        return delete.contains(IP);
    }

    @Override
    public void setRead(String IP) { this.read.add(IP); }

    @Override
    public void setWrite(String IP) { this.write.add(IP); }

    @Override
    public void setDelete(String IP) { this.delete.add(IP); }

    @Override
    public boolean revokeRead(String IP) { return this.read.remove(IP);  }

    @Override
    public boolean revokeWrite(String IP) { return this.write.remove(IP); }

    @Override
    public boolean revokeDelete(String IP) { return this.delete.remove(IP); }
}
