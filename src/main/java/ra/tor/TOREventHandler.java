package ra.tor;

import java.util.Iterator;
import java.util.logging.Logger;

public class TOREventHandler implements EventHandler {

    private final Logger out;

    public TOREventHandler(Logger LOG) {
        out = LOG;
    }

    public void circuitStatus(String status, String circID, String path) {
        out.info("Circuit "+circID+" is now "+status+" (path="+path+")");
    }
    public void streamStatus(String status, String streamID, String target) {
        out.info("Stream "+streamID+" is now "+status+" (target="+target+")");
    }
    public void orConnStatus(String status, String orName) {
        out.info("OR connection to "+orName+" is now "+status);
    }
    public void bandwidthUsed(long read, long written) {
        out.info("Bandwidth usage: "+read+" bytes read; "+ written+" bytes written.");
    }
    public void newDescriptors(java.util.List<String> orList) {
        out.info("New descriptors for routers:");
        for (Iterator<String> i = orList.iterator(); i.hasNext(); )
            out.info("   "+i.next());
    }
    public void message(String type, String msg) {
        out.info("["+type+"] "+msg.trim());
    }

    public void hiddenServiceEvent(String type, String msg) {
        out.info("hiddenServiceEvent: HS_DESC " + msg.trim());
    }

    public void hiddenServiceFailedEvent(String reason, String msg) {
        out.info("hiddenServiceEvent: HS_DESC " + msg.trim());
    }

    public void hiddenServiceDescriptor(String descriptorId, String descriptor, String msg) {
        out.info("hiddenServiceEvent: HS_DESC_CONTENT " + msg.trim());
    }

    public void unrecognized(String type, String msg) {
        out.info("unrecognized event ["+type+"] "+msg.trim());
    }

    @Override
    public void timeout() {
        out.info("The control connection to tor did not provide a response within one minute of waiting.");
    }

}
