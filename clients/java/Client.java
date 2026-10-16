import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * PQCC Java client. Usage: version | <variant> <mode> <host> <port>
 * PQCC_PROVIDER=bc registers Bouncy Castle (JCE + JSSE) at the front and uses it explicitly.
 * Trust comes only from the variant's root CA; hostname verification is on.
 */
public class Client {
    static final boolean BC = "bc".equals(System.getenv("PQCC_PROVIDER"));

    public static void main(String[] args) throws Exception {
        if (BC) {
            Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
            Security.insertProviderAt(new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(), 2);
        }
        if (args.length == 1 && args[0].equals("version")) {
            String v = System.getProperty("java.vendor") + " Java " + System.getProperty("java.runtime.version");
            if (BC) {
                v += " + BCJSSE " + Security.getProvider("BCJSSE").getVersionStr()
                   + " (BC " + Security.getProvider("BC").getVersionStr() + ")";
            }
            String schemes = System.getProperty("jdk.tls.client.SignatureSchemes");
            if (schemes != null) {
                v += " [jdk.tls.client.SignatureSchemes=" + schemes + "]";
            }
            System.out.println(v);
            return;
        }
        String variant = args[0], mode = args[1], host = args[2];
        int port = Integer.parseInt(args[3]);
        Path dir = Path.of("/certs/out", variant);

        try {
            run(dir, mode, host, port);
        } catch (Exception e) {
            System.err.println("stage failed: " + stage);
            e.printStackTrace();
            System.exit(1);
        }
    }

    static String stage = "init";

    static void run(Path dir, String mode, String host, int port) throws Exception {
        CertificateFactory cf = BC ? CertificateFactory.getInstance("X.509", "BC")
                                   : CertificateFactory.getInstance("X.509");

        stage = "parse root certificate";
        Certificate root = cf.generateCertificate(Files.newInputStream(dir.resolve("root.crt")));
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("root", root);
        TrustManagerFactory tmf = BC ? TrustManagerFactory.getInstance("PKIX", "BCJSSE")
                                     : TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        KeyManagerFactory kmf = null;
        if (mode.equals("mtls")) {
            stage = "load client certificate/key";
            X509Certificate leaf = (X509Certificate) cf.generateCertificate(Files.newInputStream(dir.resolve("client.crt")));
            Certificate inter = cf.generateCertificate(Files.newInputStream(dir.resolve("int.crt")));
            PrivateKey key = readKey(dir.resolve("client.key"), leaf.getPublicKey().getAlgorithm());
            char[] pw = "pqcc".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("client", key, pw, new Certificate[] {leaf, inter});
            kmf = BC ? KeyManagerFactory.getInstance("PKIX", "BCJSSE")
                     : KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pw);
        }

        stage = "init SSLContext";
        SSLContext ctx = BC ? SSLContext.getInstance("TLS", "BCJSSE") : SSLContext.getInstance("TLS");
        ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        stage = "handshake";
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port)) {
            s.setSoTimeout(15000);
            SSLParameters p = s.getSSLParameters();
            p.setEndpointIdentificationAlgorithm("HTTPS");
            p.setServerNames(List.of(new SNIHostName(host)));
            s.setSSLParameters(p);
            s.startHandshake();

            SSLSession sess = s.getSession();
            X509Certificate peer = (X509Certificate) sess.getPeerCertificates()[0];
            System.out.println("Provider: " + ctx.getProvider().getName());
            System.out.println("Protocol version: " + sess.getProtocol());
            System.out.println("Cipher: " + sess.getCipherSuite());
            System.out.println("Peer signature algorithm: " + peer.getSigAlgName());

            stage = "HTTP exchange";
            OutputStream out = s.getOutputStream();
            out.write("GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String line = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine();
            System.out.println("Response: " + line);
            if (line == null || !line.startsWith("HTTP/1.0 200")) {
                throw new IllegalStateException("unexpected response: " + line);
            }
        }
    }

    static PrivateKey readKey(Path pem, String alg) throws Exception {
        String b64 = Files.readString(pem).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64));
        KeyFactory kf = BC ? KeyFactory.getInstance(alg, "BC") : KeyFactory.getInstance(alg);
        return kf.generatePrivate(spec);
    }
}
