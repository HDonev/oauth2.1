package bg.mvr.dcis.oauth2.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.thymeleaf.util.StringUtils;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CustomUrlAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private String defaultFailureUrl;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    public CustomUrlAuthenticationFailureHandler(String defaultFailureUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultFailureUrl), () -> {
            return "'" + defaultFailureUrl + "' is not a valid redirect URL";
        });
        this.defaultFailureUrl = defaultFailureUrl;
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String client_id = request.getParameter("client_id");
        String errorUrl = this.defaultFailureUrl;
        if (client_id != null) {
            RegisteredClient byClientId = registeredClientRepository.findByClientId(client_id);
            if (byClientId != null) {
                errorUrl += "&client_id=" + byClientId.getClientId() + "&response_type=code&client_name=" + URLEncoder.encode(byClientId.getClientName(), UTF_8.toString());
                if (!byClientId.getRedirectUris().isEmpty()) {
                    //TODO NE E LI PO_DOBRE DA IMA SAMO EDIN redirect_uri
                    errorUrl += "&redirect_uri=" + StringUtils.join(byClientId.getRedirectUris(), " ");
                }
            }
        }
        super.setDefaultFailureUrl(errorUrl);
        super.onAuthenticationFailure(request, response, exception);
    }
}
