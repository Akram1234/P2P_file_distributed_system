import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BenchmarksFindings implements Runnable {
    PeerClient client;
    String propFilePath;

    public static void main(String []args) throws IOException, InterruptedException {
        String propFilePath = "./resources/benchmark.properties";
        BenchmarksFindings benchMark = new BenchmarksFindings(propFilePath);
        MasterServer masterServer = new MasterServer();

        masterServer.run(propFilePath);
        List<PeerClient> clients = benchMark.createClients(3);
        List<PeerServer> servers = benchMark.createServers(3);
        benchMark.runServers(servers);
        benchMark.runBenchMarks(3, clients, servers);
    }

    private void runBenchMarks(int maxThreads, List<PeerClient> clients, List<PeerServer> servers) throws InterruptedException {
        List<Thread> threads = new ArrayList<>();
        for(int i= 0; i< maxThreads; i++){
            threads.add(new Thread(new BenchmarksFindings(clients.get(i), this.propFilePath)));
        }

        long startTime = System.currentTimeMillis();

        for(Thread thread: threads) thread.start();
        for(Thread thread: threads) thread.join();

        long endTime = System.currentTimeMillis();

        System.out.println("Total Execution time " + (endTime - startTime) + " milliseconds");
    }

    private void runClients(List<PeerClient> clients) {
        for(PeerClient client: clients){
            client.run();
        }
    }

    private void runServers(List<PeerServer> servers) {
        for(PeerServer server: servers){
            server.run();
        }
    }

    private List<PeerServer> createServers(int maxPeerServers) throws IOException {
        List<PeerServer> servers = new ArrayList<>();
        for(int id=1;id<=maxPeerServers;id++){
            servers.add(new PeerServer(id, this.propFilePath));
        }
        return servers;
    }

    private List<PeerClient> createClients(int maxPeerClients) {
        List<PeerClient> clients = new ArrayList<>();
        for(int id=1;id<=maxPeerClients;id++){
            clients.add(new PeerClient(id));
        }
        return clients;
    }

    BenchmarksFindings(String propFilePath){
        this.propFilePath = propFilePath;
    }

    BenchmarksFindings(PeerClient client, String propFilePath){
        this.client = client;
        this.propFilePath = propFilePath;
    }

    @Override
    public void run() {
        System.out.println("Running for 10k create requests");
        int maxRequests= 10000;
        for(int request = 1; request<=maxRequests; request++){
            String filename = ""+request+""+System.currentTimeMillis();
            this.client.createFile( filename, "Create DATA: "+request);
            this.client.readFile( filename);
            this.client.writeFile( filename,"New DATA: "+request );
        }
    }
}
