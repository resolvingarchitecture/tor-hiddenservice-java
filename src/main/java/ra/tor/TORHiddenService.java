package ra.tor;

import ra.common.Client;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusListener;
import ra.http.server.EnvelopeJSONDataHandler;
import ra.http.server.HTTPServerService;
import ra.util.Config;
import ra.util.FileUtil;
import ra.util.RandomUtil;
import ra.util.Wait;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

public class TORHiddenService extends HTTPServerService {

    private Logger LOG = Logger.getLogger(TORHiddenService.class.getName());

    private static final String HOST = "127.0.0.1";
    private static final Integer PORT_SOCKS = 9050;
    private static final Integer PORT_CONTROL = 9051;
    //    private static final Integer PORT_CONTROL = 9100;
    private static final Integer PORT_SOCKS_BROWSER = 9150;
    private static final Integer PORT_HIDDEN_SERVICE = 9151;

    private TORControlConnection controlConnection;
    private TORHS torhs = null;
    private Properties config;

    public TORHiddenService(MessageProducer producer, ServiceStatusListener listener) {
        super(producer, listener);
    }

    TORHS getTorhs() {
        return torhs;
    }

    public int randomTORPort() {
        return RandomUtil.nextRandomInteger(10000, 65535);
    }

    @Override
    public boolean start(Properties p) {
        updateStatus(ServiceStatus.INITIALIZING);
        if(!super.start(config)){
            return false;
        }
        try {
            config = Config.loadFromClasspath("ra-tor-hiddenservice.config", p, false);
        } catch (Exception e) {
            LOG.severe(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        }
        torhs = new TORHS();
        File privKeyFile = new File(getServiceDirectory(), "private_key");
        boolean destroyHiddenService = "true".equals(config.getProperty("ra.tor.privkey.destroy"));
        if(destroyHiddenService) {
            LOG.info("Destroying Hidden Service....");
            privKeyFile.delete();
        } else if(privKeyFile.exists()) {
            LOG.info("Tor Hidden Service key found, loading...");
            byte[] bytes = null;
            try {
                bytes = FileUtil.readFile(privKeyFile.getAbsolutePath());
            } catch (IOException e) {
                LOG.warning(e.getLocalizedMessage());
                // Ensure private key is removed
                privKeyFile.delete();
            }
            if(bytes!=null) {
                torhs.fromJSON(new String(bytes));
            }
            if(torhs.virtualPort==null || torhs.targetPort==null || torhs.serviceId==null || torhs.privateKey==null) {
                // Probably corrupted file
                LOG.info("Tor key found but likely corrupted, deleting....");
                privKeyFile.delete();
            }
        }
        updateStatus(ServiceStatus.STARTING);
        try {
            controlConnection = getControlConnection();
            Map<String, String> m = controlConnection.getInfo(Arrays.asList("stream-status", "orconn-status", "circuit-status", "version"));
//            Map<String, String> m = controlConnection.getInfo(Arrays.asList("version"));
            StringBuilder sb = new StringBuilder();
            sb.append("TOR config:");
            for (Iterator<Map.Entry<String, String>> i = m.entrySet().iterator(); i.hasNext(); ) {
                Map.Entry<String, String> e = i.next();
                sb.append("\n\t"+e.getKey()+"="+e.getValue());
            }
            LOG.info(sb.toString());
            controlConnection.setEventHandler(new TOREventHandler(torhs, LOG));
            controlConnection.setEvents(Arrays.asList("CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT"));

            if(torhs.serviceId==null) {
                // Private key file doesn't exist, was unreadable, or requested to be destroyed so create a new hidden service
                privKeyFile = new File(getServiceDirectory(), "private_key");
                int virtPort = randomTORPort();
                int targetPort = randomTORPort();
                if(launch("TORHS, API, localhost, " + targetPort + ", " + EnvelopeJSONDataHandler.class.getName())) {
                    torhs = controlConnection.createHiddenService(virtPort, targetPort);
                    LOG.info("TOR Hidden Service Created: " + torhs.serviceId
                            + " on virtualPort: " + torhs.virtualPort
                            + " to targetPort: " + torhs.targetPort);
//                controlConnection.destroyHiddenService(hiddenService.serviceID);
//                hiddenService = controlConnection.createHiddenService(hiddenService.port, hiddenService.privateKey);
//                LOG.info("TOR Hidden Service Created: " + hiddenService.serviceID + " on port: "+hiddenService.port);
                    // Now save the private key
                    if (!privKeyFile.exists() && !privKeyFile.createNewFile()) {
                        LOG.warning("Unable to create file: " + privKeyFile.getAbsolutePath());
                        return false;
                    }
                    torhs.readable(true);
                    torhs.setCreatedAt(new Date().getTime());
                    FileUtil.writeFile(torhs.toJSON().getBytes(), privKeyFile.getAbsolutePath());
                } else {
                    LOG.severe("Unable to create new TOR hidden service.");
                    updateStatus(ServiceStatus.ERROR);
                    return  false;
                }
            } else if(launch("TORHS, API, localhost, " + torhs.targetPort + ", " + EnvelopeJSONDataHandler.class.getName())) {
                if(controlConnection.isHSAvailable(torhs.serviceId)) {
                    LOG.info("TOR Hidden Service available: "+torhs.serviceId
                            + " on virtualPort: "+torhs.virtualPort
                            + " to targetPort: "+torhs.targetPort);
                } else {
                    LOG.info("TOR Hidden Service not available; creating: "+torhs.serviceId);
                    torhs = controlConnection.createHiddenService(torhs.virtualPort, torhs.targetPort, torhs.privateKey);
                    LOG.info("TOR Hidden Service created: " + torhs.serviceId
                            + " on virtualPort: " + torhs.virtualPort
                            + " to targetPort: " + torhs.targetPort);
                }
            } else {
                LOG.severe("Unable to launch TOR hidden service.");
                updateStatus(ServiceStatus.ERROR);
                return false;
            }
        } catch (IOException e) {
            if(e.getLocalizedMessage().contains("Connection refused")) {
                LOG.info("Connection refused. TOR may not be installed and/or running. To install follow README.md in io/onemfive/network/sensors/tor package.");

            } else {
                LOG.warning(e.getLocalizedMessage());
            }
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOG.warning("TORAlgorithm not supported: "+e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        }
        updateStatus(ServiceStatus.RUNNING);
        return true;
    }

    private TORControlConnection getControlConnection() throws IOException {
        Socket s = new Socket("127.0.0.1", PORT_CONTROL);
        TORControlConnection conn = new TORControlConnection(s);
        conn.authenticate(new byte[0]);
        return conn;
    }

    @Override
    public boolean pause() {
        return super.pause();
    }

    @Override
    public boolean unpause() {
        return super.unpause();
    }

    @Override
    public boolean restart() {
        return super.restart();
    }

    @Override
    public boolean shutdown() {
        return super.shutdown();
    }

    @Override
    public boolean gracefulShutdown() {
        return super.gracefulShutdown();
    }

    public static void main(String[] args) {
        MessageProducer producer = new MessageProducer() {
            private Logger LOG = Logger.getLogger(MessageProducer.class.getName());
            @Override
            public boolean send(Envelope envelope) {
                LOG.info("Received Envelope: "+envelope.toJSON());
                return true;
            }

            @Override
            public boolean send(Envelope envelope, Client client) {
                LOG.info("Received Envelope: "+envelope.toJSON());
                return true;
            }
        };
        ServiceStatusListener listener = new ServiceStatusListener() {
            private Logger LOG = Logger.getLogger(ServiceStatusListener.class.getName());
            @Override
            public void serviceStatusChanged(String s, ServiceStatus serviceStatus) {
                LOG.info("Received Service Status: "+serviceStatus.name()+" on Service: "+s);
            }
        };
        Properties p = new Properties();
//        p.put("ra.tor.privkey.destroy","true");
        TORHiddenService service = new TORHiddenService(producer, listener);
        service.start(p);

        long start = new Date().getTime();

        while(service.getServiceStatus()==ServiceStatus.RUNNING) {
            Wait.aMin(1);
            long end = new Date().getTime();
            service.LOG.info("Uptime (in minutes): "+(end-start)/(60 * 1000));
        }
    }
}
