package ra.tor;

import ra.common.Client;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusListener;
import ra.http.server.EnvelopeJSONDataHandler;
import ra.http.server.HTTPServerService;
import ra.util.*;

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

    private File torUserHome;
    private File torConfigHome;
    private File torrcFile;
    private File privKeyFile;
    private File hiddenServiceDir;

    private File torhsFile;

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

        torUserHome = new File(SystemSettings.getUserHomeDir(), ".tor");
        if(!torUserHome.exists()) {
            LOG.severe("TOR User Home does not exist => TOR not installed.");
            return false;
        }

        torConfigHome = new File(config.getProperty("ra.tor.config.home"));
        if(!torConfigHome.exists()) {
            LOG.severe("TOR Config Home /etc/tor does not exist => TOR not installed.");
            return false;
        }

        torrcFile = new File(torConfigHome, "torrc");
        if(!torrcFile.exists()) {
            LOG.severe("TOR Config File /etc/tor/torrc does not exist => TOR not installed.");
            return false;
        }

        if(config.getProperty("ra.tor.hs.name")==null) {
            LOG.severe("ra.tor.hs.name (hidden service directory name) is a required property.");
            return false;
        }
        hiddenServiceDir = new File(getServiceDirectory(), config.getProperty("ra.tor.hs.name") );
        if(!hiddenServiceDir.exists() && !hiddenServiceDir.mkdir()) {
            LOG.severe("TOR hidden service directory does not exist and unable to create.");
            return false;
        }

        privKeyFile = new File(hiddenServiceDir, "private_key");

        torhsFile = new File(getServiceDirectory(), "torhs");
        if(torhsFile.exists()) {
            try {
                String json = new String(FileUtil.readFile(torhsFile.getAbsolutePath()));
                torhs.fromJSON(json);
            } catch (IOException e) {
                LOG.severe(e.getLocalizedMessage());
                return false;
            }
        }

        boolean destroyHiddenService = "true".equals(config.getProperty("ra.tor.privkey.destroy"));
        if(destroyHiddenService && privKeyFile.exists()) {
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
                torhs.privateKey = new String(bytes);
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
                privKeyFile = new File(hiddenServiceDir, "private_key");
                int virtPort;
                if(config.getProperty("ra.tor.virtualPort")==null) {
                    virtPort = randomTORPort();
                } else {
                    virtPort = Integer.parseInt(config.getProperty("ra.tor.virtualPort"));
                }
                int targetPort;
                if(config.getProperty("ra.tor.targetPort")==null) {
                    targetPort = randomTORPort();
                } else {
                    targetPort = Integer.parseInt(config.getProperty("ra.tor.targetPort"));
                }
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
                    FileUtil.writeFile(torhs.privateKey.getBytes(), privKeyFile.getAbsolutePath());
                    FileUtil.writeFile(torhs.toJSON().getBytes(), torhsFile.getAbsolutePath());

                    // Make sure torrc file is up to date
//                    List<String> torrcLines = FileUtil.readLines(torhsFile);
//                    boolean hsDirConfigured = false;
//                    boolean hsPortConfigured = false;
//                    boolean nextLine = false;
//                    String lineToRemove = null;
//                    for(String line : torrcLines) {
//                        if(!hsDirConfigured && line.equals("HiddenServiceDir "+hiddenServiceDir)) {
//                            hsDirConfigured = true;
//                            nextLine = true;
//                        }
//                        if(!hsPortConfigured && line.equals("HiddenServicePort "+ torhs.virtualPort+" 127.0.0.1:"+torhs.targetPort)) {
//                            hsPortConfigured = true;
//                        } else if(nextLine) {
//                            // Port config after our hidden service directory is old so mark for removal
//                            lineToRemove = line;
//                        }
//                    }
//                    if(!hsDirConfigured || !hsPortConfigured) {
//                        String torrcBody = new String(FileUtil.readFile(torrcFile.getAbsolutePath()));
//                        if(!hsDirConfigured)
//                            torrcBody += "\nHiddenServiceDir "+hiddenServiceDir+"\n";
//                        if(!hsPortConfigured)
//                            torrcBody += "\nHiddenServicePort "+ torhs.virtualPort+" 127.0.0.1:"+torhs.targetPort+"\n";
//                        FileUtil.writeFile(torrcBody.getBytes(), torrcFile.getAbsolutePath());
//                    }

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
