package ca.ubc.cs.cs317.dnslookup;

public class ResourceRecords {
    private ResourceRecord[] answers;
    private ResourceRecord[] nameservers;
    private ResourceRecord[] ar;


    public ResourceRecords(ResourceRecord[] answers, ResourceRecord[] nameservers, ResourceRecord[] ar) {
        this.answers = answers;
        this.nameservers = nameservers; 
        this.ar = ar;
    }

    public ResourceRecord[] getAnswers(){
        return answers;
    } 

    public ResourceRecord[] getNameServers(){
        return nameservers;
    }

    public ResourceRecord[] getAR(){
        return ar;
    }
}