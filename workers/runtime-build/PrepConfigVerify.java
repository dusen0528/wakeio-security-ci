import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class PrepConfigVerify {
    private static final Path INPUT = Path.of("/config-input");
    private static final Path RESULT = Path.of("/build-config");
    private static final String ALIAS = "wakeio-build-mirror";
    private static final String PASSWORD = "wakeio-config-v1";
    private static final byte[] USER = """
            <?xml version="1.0" encoding="UTF-8"?>
            <settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
              <localRepository>/tmp/wakeio-m2</localRepository>
              <interactiveMode>false</interactiveMode>
              <mirrors>
                <mirror>
                  <id>wakeio-build-mirror</id>
                  <mirrorOf>*</mirrorOf>
                  <url>https://wakeio-maven:8443/maven2/</url>
                </mirror>
              </mirrors>
            </settings>
            """.getBytes(StandardCharsets.UTF_8);
    private static final byte[] GLOBAL = """
            <?xml version="1.0" encoding="UTF-8"?>
            <settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"/>
            """.getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        require(args.length == 0);
        byte[] originalDer = originalCertificate();
        Map<String, Object> directory = attributes(RESULT, 040500);
        shape();
        byte[] user = read(RESULT.resolve("user-settings.xml"), USER.length);
        byte[] global = read(RESULT.resolve("global-settings.xml"), GLOBAL.length);
        require(Arrays.equals(user, USER) && Arrays.equals(global, GLOBAL));
        byte[] serialized = read(RESULT.resolve("mirror-trust.p12"), 65536);
        Security.setProperty("keystore.type.compat", "false");
        KeyStore store = KeyStore.getInstance("PKCS12", "SUN");
        require(store.getProvider().getName().equals("SUN") && store.getType().equals("PKCS12"));
        try (ByteArrayInputStream input = new ByteArrayInputStream(serialized)) {
            store.load(input, PASSWORD.toCharArray());
            require(input.available() == 0);
        }
        require(store.size() == 1);
        var aliases = store.aliases();
        require(aliases.hasMoreElements());
        require(aliases.nextElement().equals(ALIAS) && !aliases.hasMoreElements());
        require(store.isCertificateEntry(ALIAS) && !store.isKeyEntry(ALIAS));
        require(store.entryInstanceOf(ALIAS, KeyStore.TrustedCertificateEntry.class));
        KeyStore.Entry entry = store.getEntry(ALIAS, null);
        require(entry instanceof KeyStore.TrustedCertificateEntry);
        var certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
        require(certificate instanceof X509Certificate && certificate.getType().equals("X.509"));
        require(Arrays.equals(certificate.getEncoded(), originalDer));
        shape();
        require(directory.equals(attributes(RESULT, 040500)));
        byte[] output = ("{\"schema\":\"wakeio.prep-config.verify/v1\","
                + "\"storeType\":\"PKCS12\",\"storeProvider\":\"SUN\","
                + "\"aliases\":[\"wakeio-build-mirror\"],\"trustedCertificateEntries\":1,\"keyEntries\":0,"
                + "\"certificateDerSha256\":\"" + sha256(originalDer) + "\","
                + "\"storeSha256\":\"" + sha256(serialized) + "\","
                + "\"userSettingsSha256\":\"" + sha256(user) + "\","
                + "\"globalSettingsSha256\":\"" + sha256(global) + "\"}\n").getBytes(StandardCharsets.UTF_8);
        require(output.length <= 2048);
        System.out.write(output);
        System.out.flush();
        require(!System.out.checkError());
    }

    private static byte[] originalCertificate() throws Exception {
        attributes(INPUT, 040500);
        byte[] pem = read(INPUT.resolve("mirror.crt"), 16384);
        var matcher = Pattern.compile("\\A-----BEGIN CERTIFICATE-----\\n"
                + "([A-Za-z0-9+/]+={0,2}(?:\\n[A-Za-z0-9+/]+={0,2})*)"
                + "\\n-----END CERTIFICATE-----\\n\\z")
                .matcher(new String(pem, StandardCharsets.US_ASCII));
        require(matcher.matches());
        String payload = matcher.group(1).replace("\n", "");
        byte[] der = Base64.getDecoder().decode(payload);
        require(der.length > 0 && Base64.getEncoder().encodeToString(der).equals(payload));
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
        require(factory.getProvider().getName().equals("SUN") && factory.getType().equals("X.509"));
        try (ByteArrayInputStream input = new ByteArrayInputStream(der)) {
            var parsed = factory.generateCertificate(input);
            require(parsed instanceof X509Certificate && input.available() == 0);
            require(parsed.getType().equals("X.509") && Arrays.equals(parsed.getEncoded(), der));
            return parsed.getEncoded();
        }
    }

    private static Map<String, Object> attributes(Path path, int mode) throws IOException {
        Map<String, Object> values = Files.readAttributes(path, "unix:dev,ino,mode,nlink,uid,gid,size",
                LinkOption.NOFOLLOW_LINKS);
        require(((Number) values.get("mode")).intValue() == mode);
        require(((Number) values.get("uid")).longValue() == 65532);
        require(((Number) values.get("gid")).longValue() == 65532);
        if ((mode & 0170000) == 0100000) {
            require(((Number) values.get("nlink")).longValue() == 1);
        }
        return values;
    }

    private static byte[] read(Path path, int maximum) throws IOException {
        Map<String, Object> before = attributes(path, 0100400);
        long size = ((Number) before.get("size")).longValue();
        require(size > 0 && size <= maximum);
        ByteBuffer bytes = ByteBuffer.allocate(maximum + 1);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            while (channel.read(bytes) != -1) {
                require(bytes.position() <= maximum);
            }
            require(channel.size() == size && bytes.position() == size);
            require(before.equals(attributes(path, 0100400)));
        }
        return Arrays.copyOf(bytes.array(), bytes.position());
    }

    private static void shape() throws IOException {
        Set<String> expected = new HashSet<>(Set.of("user-settings.xml", "global-settings.xml", "mirror-trust.p12"));
        try (var entries = Files.newDirectoryStream(RESULT)) {
            for (Path entry : entries) {
                require(expected.remove(entry.getFileName().toString()));
                attributes(entry, 0100400);
            }
        }
        require(expected.isEmpty());
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256", "SUN").digest(bytes));
    }

    private static void require(boolean condition) throws IOException {
        if (!condition) {
            throw new IOException("Invalid preparation configuration");
        }
    }
}
