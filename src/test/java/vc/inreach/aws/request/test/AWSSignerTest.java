package vc.inreach.aws.request.test;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import org.junit.Test;
import vc.inreach.aws.request.AWSSigner;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Supplier;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

public class AWSSignerTest {
    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (get-vanilla.*)
     * <p>
     * GET / http/1.1
     * Date:Mon, 09 Sep 2011 23:36:00 GMT
     * Host:host.foo.com
     *
     * @throws Exception
     */
    @Test
    public void testGetVanilla() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Date", date);
        headers.put("Host", host + ":80");
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }

    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (post-vanilla-query.*)
     * <p>
     * POST /?foo=bar http/1.1
     * Date:Mon, 09 Sep 2011 23:36:00 GMT
     * Host:host.foo.com
     *
     * @throws Exception
     */
    @Test
    public void testPostVanillaQuery() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "POST";
        Map<String, List<String>> queryParams = new HashMap<>();
                queryParams.put("foo", Collections.singletonList("bar"));
        Map<String, Object> headers = new HashMap<>();
                headers.put("Date", date);
                headers.put("Host", host);
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }

    /**
     * Test case for signing an index request with an encodable id
     *
     * @throws Exception
     */
    @Test
    public void testPostEncodeableId() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "service";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2015, 8, 30, 12, 36, 0);
        String date = "20150830T123600Z";

        // HTTP request
        String host = "example.amazonaws.com";
        String uri = "/index_name/type_name/joe@example.com";
        String method = "PUT";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("X-Amz-Date", date);
        headers.put("Host", host);
        String body = "{\n"
                + "    \"user\" : \"kimchy\",\n"
                + "    \"post_date\" : \"2009-11-15T14:12:12\",\n"
                + "    \"message\" : \"trying out Elasticsearch\"\n"
                + "}";
        Optional<byte[]> payload = Optional.of(body.getBytes("utf-8"));

        String expectedAuthorizationHeader = SkdSignerUtil.getExpectedAuthorizationHeader(
                new SkdSignerUtil.Request()
                        .setServiceName(service)
                        .setRegion(region)
                        .setDate( new SimpleDateFormat("yyyyMMdd'T'HHmmssXXX").parse(date))
                        .setHost(host)
                        .setUri(uri)
                        .setHttpMethod(method)
                        .setHeaders(headers)
                        .setQueryParams(queryParams)
                        .setCredentialsProvider(awsCredentialsProvider)
                        .setBody(body)
        );

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
    }

    /**
     * Test case for signing an index request with an encodable id
     *
     * @throws Exception
     */
    @Test
    public void testPostEncodedId() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "service";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2015, 8, 30, 12, 36, 0);
        String date = "20150830T123600Z";

        // HTTP request
        String host = "example.amazonaws.com";
        String uri = "/index_name/type_name/joe%40example.com";
        String method = "PUT";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("X-Amz-Date", date);
        headers.put("Host", host);
        String body = "{\n"
                + "    \"user\" : \"kimchy\",\n"
                + "    \"post_date\" : \"2009-11-15T14:12:12\",\n"
                + "    \"message\" : \"trying out Elasticsearch\"\n"
                + "}";
        Optional<byte[]> payload = Optional.of(body.getBytes("utf-8"));

        String expectedAuthorizationHeader = SkdSignerUtil.getExpectedAuthorizationHeader(
                new SkdSignerUtil.Request()
                        .setServiceName(service)
                        .setRegion(region)
                        .setDate( new SimpleDateFormat("yyyyMMdd'T'HHmmssXXX").parse(date))
                        .setHost(host)
                        .setUri(uri)
                        .setHttpMethod(method)
                        .setHeaders(headers)
                        .setQueryParams(queryParams)
                        .setCredentialsProvider(awsCredentialsProvider)
                        .setBody(body)
        );

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
    }

    @Test
    public void testGetVanillaWithoutDateHeader() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "20110909T233600Z";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Host", host);
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "904f8c568bca8bd2618b9241a7f2a8d90f279e717fd0f6727af189668b040151";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("X-Amz-Date");
        assertThat(caseInsensitiveSignedHeaders.get("X-Amz-Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("Date");
    }

    @Test
    public void testGetVanillaWithTempCreds() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        String sessionToken = "AKIDEXAMPLESESSION";
        AWSCredentials credentials = new BasicSessionCredentials(awsAccessKey, awsSecretKey, sessionToken);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Date", date);
        headers.put("Host", host);
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "43abd9e63c148feb91c43fe2c9734eb44b7eb16078d484d3ff9b6249b62fdc60";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host;x-amz-security-token, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
        assertThat(caseInsensitiveSignedHeaders).containsKey("X-Amz-Security-Token");
        assertThat(caseInsensitiveSignedHeaders.get("X-Amz-Security-Token")).isEqualTo(sessionToken);
    }

    @Test
    public void testGetVanillaBase64QueryParam() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put("scrollId", Collections.singletonList("dGVzdA==="));
        Map<String, Object> headers = new HashMap<>();
        headers.put("Date", date);
        headers.put("Host", host + ":80");
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "ebec182ae6456633a8fecbd2737e60d6aec6b0da9cfa5731457e71edec83fde3";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }

    @Test
    public void testGetQueryParamWithAsterisks() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put("_query", Collections.singletonList("ben*"));

        Map<String, Object> headers = new HashMap<>();
        headers.put("Date", date);
        headers.put("Host", host + ":80");
        Optional<byte[]> payload = Optional.empty();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b108a8b23c3a760dc3b197ec480b20d9c9e210f4a389077f5721e458e30350bf";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
        );

        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }

    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (get-utf8.*)
     * <p>
     * GET /ሴ HTTP/1.1
     * Host:example.amazonaws.com
     * X-Amz-Date:20150830T123600Z
     *
     * @throws Exception
     */
    @Test
    public void testGetUtf8() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "service";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2015, 8, 30, 12, 36, 0);
        String date = "20150830T123600Z";

        // HTTP request
        String host = "example.amazonaws.com";
        String uri = "/ሴ";
        String method = "GET";
        Map<String, List<String>> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        headers.put("Host", host);
        headers.put("X-Amz-Date", date);
        Optional<byte[]> payload = Optional.empty();

        String expectedAuthorizationHeader = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85";

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
    }

}
