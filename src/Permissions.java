public interface Permissions {

    public boolean canRead(String IP);
    public boolean canWrite(String IP);
    public boolean canDelete(String IP);

    public void setRead(String IP);
    public void setWrite(String IP);
    public void setDelete(String IP);

    public boolean revokeRead(String IP);
    public boolean revokeWrite(String IP);
    public boolean revokeDelete(String IP);

}
