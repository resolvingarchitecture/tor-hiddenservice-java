package ra.tor;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import ra.common.network.NetworkBuilderStrategy;
import ra.common.network.NetworkPeer;
import ra.util.Wait;

import java.util.Properties;
import java.util.logging.Logger;

/**
 * Hidden Service creation can be verified in Linux
 * at /etc/tor/torrc file
 */
public class TorHiddenServiceTest {

    private static final Logger LOG = Logger.getLogger(TorHiddenServiceTest.class.getName());

    private static NetworkPeer orig;
    private static NetworkPeer dest;
    private static MockProducerClient mockProducerClient;
    private static TORClientService clientService;
    private static MockProducerService mockProducerService;
    private static TORHiddenService hiddenService;
    private static TORHS torhs;
    private static Properties props;
    private static boolean serviceRunning = false;

    @BeforeClass
    public static void init() {
        LOG.info("Init...");
        props = new Properties();
        props.put("ra.tor.privkey.destroy", "true");
        mockProducerClient = new MockProducerClient();
        clientService = new TORClientService(mockProducerClient, null, new NetworkBuilderStrategy());
        clientService.start(props);
        orig = new NetworkPeer("Tor");
        orig.setId("afiome3290jLkf.onion");
        orig.setPort(1234);
        hiddenService = new TORHiddenService(mockProducerService, null);
        serviceRunning = hiddenService.start(props);
        torhs = hiddenService.getTorhs();
        dest = new NetworkPeer("Tor");
        dest.setId(torhs.serviceId+".onion");
        dest.setPort(torhs.virtualPort);
        // Wait 20 seconds to allow Tor hidden service to broadcast its address on the Tor network
        Wait.aSec(20);
    }

    @AfterClass
    public static void tearDown() {
        LOG.info("Teardown...");
        hiddenService.gracefulShutdown();
    }

//    @Test
//    public void initializedTest() {
//        Assert.assertTrue(serviceRunning);
//    }

    /**
     * Send an op message to the hidden service and verify op reply.
     */
//    @Test
//    public void peer2Peer() {
//        Envelope e = Envelope.documentFactory();
//        DLC.addExternalRoute(TORClientService.class, HTTPClientService.OPERATION_SEND, e, orig, dest);
//        DLC.mark("op", e);
//        // Ratchet route for testing
////        e.getDynamicRoutingSlip().nextRoute();
//        clientService.handleDocument(e);
//        Assert.assertTrue("{op=200}".equals(DLC.getContent(e)));
//    }
}
