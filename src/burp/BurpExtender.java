package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements  IBurpExtender, IScannerCheck, IScannerInsertionPointProvider {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> scannedURLs;
    private final int sessionIdLength = 24;
    private final String sessionIdAlphabet = "abcdefghijklmnopqrstuvwxyz012345";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.scannedURLs = new HashSet<String>();

        callbacks.setExtensionName("ASP.NET Cookieless Session Scanner");
        callbacks.registerScannerCheck(this);
        callbacks.registerScannerInsertionPointProvider(this);
    }

    private String generateSessionId() {
        StringBuilder builder = new StringBuilder(sessionIdLength);
        Random random = new Random();
        while (builder.length() < sessionIdLength) {
            int r = random.nextInt(sessionIdAlphabet.length());
            builder.append(sessionIdAlphabet.charAt(r));
        }
        return builder.toString();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        // Don't scan the same host more than once. We don't care about insertion points here, and we don't care about
        // the same path with different query strings and fragments
        URL url = helpers.analyzeRequest(basePair).getUrl();
        String query = url.getQuery();
        String pathless;
        if (query != null) {
            pathless = url.toString().replace("?" + url.getQuery(), "");
        } else {
            pathless = url.toString();
        }

        if (this.scannedURLs.contains((pathless))) {
            return null;
        }

        this.scannedURLs.add(pathless);

        // Generate and send the new request
        String path = url.getPath();
        String sessionId = generateSessionId();
        String payload = "(S(" + sessionId + "))";
        String newPath = "/" + payload + path;
        String testRequest = helpers.bytesToString(basePair.getRequest()).replaceFirst(path, newPath);
        IHttpRequestResponse newPair = callbacks.makeHttpRequest(basePair.getHttpService(),
                helpers.stringToBytes(testRequest));

        // Check if the new response contains our payload
        int bodyOffset = helpers.analyzeResponse(newPair.getResponse()).getBodyOffset();
        List<int[]> responseMatches = getMatches(newPair.getResponse(), helpers.stringToBytes(sessionId), bodyOffset);
        if (responseMatches.size() == 0) {
            return null;
        }

        // Create the issue
        List<IScanIssue> issues = new ArrayList<>(1);
        List<int[]> requestMatches = getMatches(newPair.getRequest(), helpers.stringToBytes(payload), 0);
        short newCode = helpers.analyzeResponse(newPair.getResponse()).getStatusCode();
        short oldCode = helpers.analyzeResponse(basePair.getResponse()).getStatusCode();
        String confidence;
        if (newCode >= 300 || newCode != oldCode) {
            confidence = "Tentative";
        } else {
            confidence = "Firm";
        }
        issues.add(new CustomScanIssue(
                newPair.getHttpService(),
                helpers.analyzeRequest(basePair).getUrl(),
                new IHttpRequestResponse[] {callbacks.applyMarkers(newPair, requestMatches, responseMatches)},
                sessionId,
                confidence
        ));

        return issues;
    }

    // From https://github.com/PortSwigger/example-scanner-checks/blob/master/java/BurpExtender.java
    private List<int[]> getMatches(byte[] target, byte[] match, int start) {
        List<int[]> matches = new ArrayList<int[]>();
        while (start < target.length) {
            start = helpers.indexOf(target, match, true, start, target.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        return matches;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // If this method is being called, something that gone wrong for our host checking.
        return -1;
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse basePair) {
        // Check if a cookieless session in the path
        String path = helpers.analyzeRequest(basePair).getUrl().getPath();
        Pattern p = Pattern.compile("^/\\([A-Z]\\(([a-z0-5]{24})\\)\\)");
        Matcher m = p.matcher(path);
        if (!m.find()) {
            return null;
        }

        String sessionId = m.group(1);
        List<IScannerInsertionPoint> insertions = new ArrayList<IScannerInsertionPoint>();
        insertions.add(new CustomInsertionPoint(basePair.getRequest(), sessionId));
        return insertions;
    }

    class CustomInsertionPoint implements IScannerInsertionPoint {
        private String sessionId;
        private int insertionStart;
        private byte[] baseRequest;

        public CustomInsertionPoint(byte[] request, String sessionId) {
            this.sessionId = sessionId;
            this.insertionStart = helpers.bytesToString(request).indexOf(sessionId);
            this.baseRequest = request;
        }

        @Override
        public String getInsertionPointName() {
            return "ASP.NET Cookieless Session";
        }

        @Override
        public String getBaseValue() {
            return this.sessionId;
        }

        @Override
        public byte[] buildRequest(byte[] payload) {
            // Replace the sessionId
            byte[] newReq = new byte[baseRequest.length - sessionIdLength + payload.length];
            System.arraycopy(baseRequest, 0, newReq, 0, insertionStart);
            System.arraycopy(payload, 0, newReq, insertionStart, payload.length);
            System.arraycopy(baseRequest, insertionStart+sessionIdLength, newReq, insertionStart+payload.length, baseRequest.length - insertionStart - sessionIdLength);
            return newReq;
        }

        @Override
        public int[] getPayloadOffsets(byte[] payload) {
            return new int[]{insertionStart, insertionStart + payload.length};
        }

        @Override
        public byte getInsertionPointType() {
            //return INS_EXTENSION_PROVIDED;
            return INS_URL_PATH_FOLDER;
        }
    }
}

class CustomScanIssue implements IScanIssue {
    private final String name = "ASP.NET Cookieless Sessions Supported";
    private final String severity = "High";

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String confidence;
    private String sessionId;

    public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String sessionId,
                            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.sessionId = sessionId;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
        return this.url;
    }

    @Override
    public String getIssueName() {
        return this.name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return this.severity;
    }

    @Override
    public String getConfidence() {
        return this.confidence;
    }

    @Override
    public String getIssueBackground() {
        return "For more information, see https://blog.isec.pl/all-is-xss-that-comes-to-the-net/";
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return "The web server reflected back the session ID " + sessionId + " when it was passed as a "
                + "cookieless session. This can often lead to XSS and other client side injections.";
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return this.httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }
}

