package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.DatagramPacket;
import java.net.UnknownHostException;
import java.net.InetSocketAddress;
import java.util.*;
import java.nio.ByteBuffer;
import java.util.Arrays;



public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();
    /*
    private static Map<String, Integer>map = Map.of("A",1,"CNAME",5,"NS",2,"AAAA",28);
    */

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        byte b = 0;
        retrieveResultsFromServer(node,rootServer);

        // TODO To be completed by the student

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // TODO change allocate to 512 
        ByteBuffer byteOutput = ByteBuffer.allocate(512);
        int id = FillHeaderQuery(false,byteOutput);
        FillQuestionSection(node, byteOutput);
        System.out.println("Sending Request");
        System.out.println(bytesToHexString(byteOutput.array()));

        byte[] b = byteOutput.array();
        byte[] b2 = Arrays.copyOfRange(b, 0, byteOutput.position());
        DatagramPacket packet = new DatagramPacket(b,b.length,server,53);
        // Send Packet; 
        try {
            socket.send(packet);
            socket.setSoTimeout(5000);
        } catch (SocketTimeoutException ex){
            // Try to resend time out 
            try {
                socket.send(packet);
                socket.setSoTimeout(5000);
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            } 
        } catch (IOException exp) {
                exp.printStackTrace();
                System.exit(1);
        }
        // receive Packet
        byte[] bytes = new byte[1024];
        DatagramPacket recievedpacket = new DatagramPacket(bytes,bytes.length);
        
        try {
            socket.receive(recievedpacket);
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        ByteBuffer byteInput = ByteBuffer.wrap(bytes);
        // Check the header of the reponse to see if valid 
        System.out.println("receiving packet");
        System.out.println(bytesToHexString(byteInput.array()));
        HeaderResponse headerRes = DecodeHeaderResponse(id,byteInput);
        

    }

   public static HeaderResponse DecodeHeaderResponse(int id, ByteBuffer byteInput) {
        // Checks Header to make sure proper id code returned 
        boolean isError = false;
        byte[] headerInt = new byte[2];
        byteInput.get(headerInt,0,2);
        int getInt = 0;
        for (int i = 0 ; i < headerInt.length; i++) {
            getInt = getInt | (((headerInt[i] & 0xff) << (headerInt.length - i - 1) * 8));
        }
        if (getInt != id) {
            System.out.printf("Error: incorrect header id %d, expected %d\n",getInt,id);
            isError = true;
        }

        byte b3 = byteInput.get();
        int b3toInt = ((b3 & 0xff) >>> 7);
        if (b3toInt !=  1){
            System.out.printf("Error: QR expected 1, but got %d\n",b3toInt);
        }
        System.out.printf("Authoriative is %02x\n",b3 & 0x4);
        boolean authoriative = ((b3 & 0x4) >> 2) == 1;

        // Checks RCODE to make sure no error
        int b4 = (byteInput.get() & 0x0f);
        System.out.printf("RCODE is %02x\n",b4);


        if (b4 != 0) {
            System.out.printf("Error: incorrect RCODE %d, expected 0",b4);
            isError = true;
        }

        // QDCOUnt // Change to some sort of loop
        byte[] bytes = new byte[2];
        byteInput.get(bytes,0,2);
        int questionCount = BytestoInt(bytes);
        byteInput.get(bytes,0,2);
        int answerCount = BytestoInt(bytes);
        byteInput.get(bytes,0,2);
        int nsCount = BytestoInt(bytes);
        byteInput.get(bytes,0,2);
        int arCount = BytestoInt(bytes);
        HeaderResponse header = new HeaderResponse(0,questionCount,answerCount,nsCount,arCount,authoriative,isError);
        return header;
    }

    public static void DecodeResourceRecord(ByteBuffer byteInput){
        // TODO: Call Alvi's f(x)
        byte[] bytes = new byte[2];
        byteInput.get(bytes,0,2);
        RecordType type = RecordType.getByCode(BytestoInt(bytes));
        byteInput.get(bytes,0,2);
        int classRR = BytestoInt(bytes);
        byteInput.get(bytes,0,4);
        long ttl = BytestoLong(bytes);
        bytes = new byte[2];
        byteInput.get(bytes,0,2);
        int rdLength = BytestoInt(bytes);
        // TODO: Call Alvi's f(x)
        return;
    }

    public static int BytestoInt(byte[] bytes) {
        int getInt = 0;
        for (int i = 0 ; i < bytes.length; i++) {
            getInt = getInt | (((bytes[i] & 0xff) << (bytes.length - i - 1) * 8));
        }
        return getInt;
    }

    public static long BytestoLong(byte[] bytes) {
        long getInt = 0;
        for (int i = 0 ; i < bytes.length; i++) {
            getInt = getInt | (((bytes[i] & 0xff) << (bytes.length - i - 1) * 8));
        }
        return getInt;
    }


    // Method to print bytes to HexString 
    public static String bytesToHexString(byte[] bytes){ 
        StringBuilder sb = new StringBuilder(); 
        for(byte b : bytes){ sb.append(String.format("%02x", b&0xff)); 
    } 
    return sb.toString(); 
} 

    // Fills the Header Querry
    // THis is a gross function. 
    private static int FillHeaderQuery(boolean response, ByteBuffer byteOutput) {
        // some arbitary number
        // Allocate Random Random
        Random r = new Random();
        int randInt = r.nextInt(65535);
        System.out.println(randInt);
        byteOutput.put((byte) (randInt >>> 8));
        byteOutput.put((byte) randInt);

        // TODO; Need to put these into byte array 
        // This byte sets QR|   Opcode  |AA|TC|RD|RA
        byteOutput.put((byte) 0);
        // |RA|   Z    |   RCODE   | 
        byteOutput.put((byte) 0);
        //  QDCOUNT
        byteOutput.put((byte) 0);
        byteOutput.put((byte) 1);
        // ANCOUNT
        byteOutput.put((byte) 0);
        byteOutput.put((byte) 0);
        // NSCOUNT
        byteOutput.put((byte) 0);
        byteOutput.put((byte) 0);
        // ARCOUNT
        byteOutput.put((byte) 0);
        byteOutput.put((byte) 0);
        System.out.println("Generated Query Header");
        System.out.println(byteOutput.toString());


        return randInt;
    }
    // TODO:
    // What if we send the request with the same ID? 

    // Fills out the Question Section into the ByteBuffer 
    private static ByteBuffer FillQuestionSection(DNSNode node, ByteBuffer byteOutput) {
        System.out.println("Entering Fill Question Section");
        // Generates QNAME 
        // loop through the string and change each element to a char and cast
        // it to a byte and place in byte array
        // QNAME
        String str = node.getHostName();
        String[] strsSplit = str.split("\\.");
        System.out.println(strsSplit);
        byte[] b = new byte[str.length() + 2];
        int bytelen = 0;
        for (int i = 0; i < strsSplit.length; i++){
            b[bytelen] = (byte) strsSplit[i].length();
            bytelen +=1;
            for (int j = 0; j < strsSplit[i].length();j++) {
                b[bytelen] = (byte) strsSplit[i].charAt(j);
                bytelen+=1;
        }
    }

        // add terminator 
        b[str.length() + 1] = 0;
        System.out.print(bytesToHexString(b));
        byteOutput.put(b);
        // QTYPE  4 bits

        int qCode = node.getType().getCode();
        System.out.println(qCode);
        byteOutput.put((byte) (qCode >>> 8));
        byteOutput.put((byte) qCode);
        // QCLASS -- IN -- 1 
        byteOutput.put((byte) 0);
        byteOutput.put((byte) 1);

        return byteOutput;
    }


    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

}
