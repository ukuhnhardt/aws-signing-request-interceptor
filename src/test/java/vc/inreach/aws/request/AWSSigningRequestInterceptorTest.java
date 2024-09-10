package vc.inreach.aws.request;

import com.amazonaws.util.SdkHttpUtils;
import org.apache.http.Header;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.message.BasicRequestLine;
import org.apache.http.protocol.HttpContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URI;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@RunWith(MockitoJUnitRunner.class)
public class AWSSigningRequestInterceptorTest {

    @Mock
    private AWSSigner signer;
    @Mock
    private HttpRequestWrapper request;
    @Mock
    private HttpContext context;

    private AWSSigningRequestInterceptor interceptor;

    @Before
    public void setUp() throws Exception {
        interceptor = new AWSSigningRequestInterceptor(signer);
    }

    @Test
    public void noQueryParams() throws Exception {
        final String url = "http://someurl.com";
        final Map<String, List<String>> queryParams = new HashMap<>();

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }


    @Test
    public void queryParamsSupportValuesWithSpaceEncodedAsPlus() throws Exception {
        final String url = "http://someurl.com?a=b+c";
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put("a", Arrays.asList("b c"));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }

    @Test
    public void queryParamsSupportValuesWithAmpersand() throws Exception {
        final String valueWithAmpersand = "a & b";
        final String encodedValue = SdkHttpUtils.urlEncode(valueWithAmpersand, false);
        final String url = "http://someurl.com?a=" + encodedValue + "&c=d";
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put("a", Arrays.asList(valueWithAmpersand));
        queryParams.put("c", Arrays.asList("d"));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }


    @Test
    public void queryParamsSupportValuesWithEquals() throws Exception {
        final String key = "scroll_id";
        final String value = "c2NhbjsxOzc3Mjo5WGljUUFNeVJGcVdDSzBjaUVQcDJ3OzE7dG90YWxfaGl0czo1NTg0Ow==";
        final String url = "http://someurl.com?" + key + "=" + value;
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put(key, Arrays.asList(value));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }

    @Test
    public void queryParamsSupportValuesWithoutEquals() throws Exception {
        final String key = "scroll_id";
        final String url = "http://someurl.com?" + key;
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put(key, Arrays.asList(""));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }

    @Test
    public void queryParamsSupportEmptyValues() throws Exception {
        final String key = "a";
        final String url = "http://someurl.com?" + key + "=";
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put(key, Arrays.asList(""));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }

    @Test
    public void emptyQueryParams() throws Exception {
        final String key = "a";
        final String value = "b";
        final String url = "http://someurl.com?" + key + "=" + value + "&";
        final Map<String, List<String>> queryParams = new HashMap<>();
        queryParams.put(key, Arrays.asList(value));

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class))).thenReturn(Map.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMap(), any(Optional.class));
    }

    private void mockRequest(String url) throws Exception {
        when(request.getURI()).thenReturn(new URI(url));
        when(request.getRequestLine()).thenReturn(new BasicRequestLine("GET", url, new ProtocolVersion("HTTP", 1, 1)));
        when(request.getAllHeaders()).thenReturn(new Header[]{});
        when(request.getOriginal()).thenReturn(request);
    }
}
