package vc.inreach.aws.request.test;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import org.junit.Test;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;

public class SkdSignerUtilTest {

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
        String date = "20150830T123600Z";

        // HTTP request
        String host = "example.amazonaws.com";
        String uri = "/ሴ";
        String method = "GET";
        Map<String, String> queryParams = new HashMap<>();
        Map<String, Object> headers = new HashMap<String, Object>() {{
            put("Host", host);
            put("X-Amz-Date", date);
        }};

        // expected auth header as per test suite
        String expectedAuthorizationHeader = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85";

        // WHEN
        // The request is signed
        String actualAuthorizationHeader = SkdSignerUtil.getExpectedAuthorizationHeader(
                new SkdSignerUtil.Request()
                        .setServiceName(service)
                        .setRegion(region)
                        .setDate( new SimpleDateFormat("yyyyMMdd'T'HHmmssXXX").parse(date))
                        .setHost(host)
                        .setUri(uri)
                        .setHttpMethod(method)
                        .setHeaders(headers)
                        .setCredentialsProvider(awsCredentialsProvider)
        );

        // THEN
        assertEquals("Header does not match", expectedAuthorizationHeader, actualAuthorizationHeader);
    }

    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (post-vanilla-query.*)
     *
     * POST /?Param1=value1 HTTP/1.1
     * Host:example.amazonaws.com
     * X-Amz-Date:20150830T123600Z
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
        String service = "service";

        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2015, 8, 30, 12, 36, 0);
        String date = "20150830T123600Z";

        // HTTP request
        String host = "example.amazonaws.com";
        String uri = "/";
        String method = "POST";
        Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put("Param1", Collections.singletonList("value1"));

        Map<String, Object> headers = new HashMap<>();
        headers.put("X-Amz-Date", date);
        headers.put("Host", host);
        Optional<byte[]> payload = Optional.empty();

        // expected auth header as per test suite
        String expectedAuthorizationHeader = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11";

        // WHEN
        // The request is signed
        String actualAuthorizationHeader = SkdSignerUtil.getExpectedAuthorizationHeader(
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
        );

        // THEN
        assertEquals("Header does not match", expectedAuthorizationHeader, actualAuthorizationHeader);
    }

}
