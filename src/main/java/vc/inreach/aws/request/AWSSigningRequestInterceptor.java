package vc.inreach.aws.request;

//import com.google.common.base.Function;

//import com.google.common.base.Optional;
//import com.google.common.base.Strings;
//import com.google.common.base.Throwables;
//import com.google.common.io.ByteStreams;

import org.apache.http.*;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class AWSSigningRequestInterceptor implements HttpRequestInterceptor {

//    private static final Splitter SPLITTER = Splitter.on('&').trimResults().omitEmptyStrings();

    private static final Pattern SPLITTER = Pattern.compile("&");
    private final AWSSigner signer;

    public AWSSigningRequestInterceptor(AWSSigner signer) {
        this.signer = signer;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        request.setHeaders(
                headers(
                        signer.getSignedHeaders(
                                path(request),
                                request.getRequestLine().getMethod(),
                                params(request),
                                headers(request),
                                body(request))
                ));
    }

    private Map<String, List<String>> params(HttpRequest request) throws IOException {
        final String rawQuery = ((HttpRequestWrapper) request).getURI().getRawQuery();
        if (isNullOrEmpty(rawQuery))
            return Map.of();

//        final Iterable<String> rawParams = SPLITTER.split(rawQuery);
        final Iterable<String> rawParams = SPLITTER.splitAsStream(rawQuery)
                .filter(s -> !s.isBlank())
                .collect(Collectors.toList());
        return params(rawParams);
    }


    private Map<String, List<String>> params(Iterable<String> rawParams) throws IOException {
//        final ImmutableListMultimap.Builder<String, String> queryParams = ImmutableListMultimap.builder();
        final Map<String, List<String>> queryParams = new HashMap<>();

        for (String rawParam : rawParams) {
            if (!isNullOrEmpty(rawParam)) {
                final String pair = URLDecoder.decode(rawParam, StandardCharsets.UTF_8.name());
                final int index = pair.indexOf('=');
                if (index > 0) {
                    final String key = pair.substring(0, index);
                    final String value = pair.substring(index + 1);
//                    queryParams.put(key, value);
                    queryParams.compute(key, new BiFunction<String, List<String>, List<String>>() {
                        @Override
                        public List<String> apply(String s, List<String> strings) {
                            if (strings == null) {
                                return new ArrayList<>();
                            }
                            return strings;
                        }
                    }).add(value);
                } else {
                    queryParams.put(pair, Arrays.asList(""));
                }
            }
        }

        return queryParams;
    }

    private String path(HttpRequest request) {
        return ((HttpRequestWrapper) request).getURI().getRawPath();
    }

    private Map<String, Object> headers(HttpRequest request) {
//        final ImmutableMap.Builder<String, Object> headers = ImmutableMap.builder();
        if(request.getAllHeaders().length == 0) {
            return Map.of();
        }
        final Map<String, Object> headers = new HashMap<>();
        for (Header header : request.getAllHeaders()) {
            headers.put(header.getName(), header.getValue());
        }

        return headers;
    }

    private Optional<byte[]> body(HttpRequest request) throws IOException {
        final HttpRequest original = ((HttpRequestWrapper) request).getOriginal();
        if (!HttpEntityEnclosingRequest.class.isAssignableFrom(original.getClass())) {
            return Optional.empty();
        }
        return Optional.ofNullable(((HttpEntityEnclosingRequest) original).getEntity()).map(TO_BYTE_ARRAY);
    }

    private Header[] headers(Map<String, Object> from) {
        return from.entrySet().stream()
                .map(entry -> new BasicHeader(entry.getKey(), entry.getValue().toString()))
                .collect(Collectors.toList())
                .toArray(new Header[from.size()]);
    }

    private static final Function<HttpEntity, byte[]> TO_BYTE_ARRAY = entity -> {
        try {
//            return ByteStreams.toByteArray(entity.getContent());
            return entity.getContent().readAllBytes();
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return "".getBytes(StandardCharsets.UTF_8);
        }
    };

    private static boolean isNullOrEmpty(String rawQuery) {
        return Objects.isNull(rawQuery) || rawQuery.isEmpty();
    }

}
