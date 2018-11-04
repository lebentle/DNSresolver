package ca.ubc.cs.cs317.dnslookup;

public class HeaderResponse {
    public boolean authoritative;
    public boolean isError;   
    public int qdcount;
    public int ancount;
    public int nscount;
    public int arcount;
    public int responseID;


    public HeaderResponse(int responseID, int qdcount, int ancount, int nscount, int arcount, boolean authoritative, boolean isError) {
        this.qdcount = qdcount;
        this.ancount = ancount; 
        this.nscount = nscount;
        this.arcount = arcount;
        this.authoritative = authoritative;
        this.responseID = responseID;
        this.isError = isError;
    }
}