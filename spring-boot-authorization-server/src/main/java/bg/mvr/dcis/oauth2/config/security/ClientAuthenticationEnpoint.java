package bg.mvr.dcis.oauth2.config.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.thymeleaf.util.StringUtils;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import static java.nio.charset.StandardCharsets.UTF_8;

public class ClientAuthenticationEnpoint implements AuthenticationEntryPoint {
    private String loginUri;
    private RegisteredClientRepository registeredClientRepository;

    public ClientAuthenticationEnpoint(String loginUri, RegisteredClientRepository registeredClientRepository) {
        this.loginUri = loginUri;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        AuthenticationEntryPoint authenticationEntryPoint;
        String client_id = request.getParameter("client_id");
        String clientUri = loginUri;
        if (client_id != null) {
            RegisteredClient byClientId = registeredClientRepository.findByClientId(client_id);
            if (byClientId != null) {
                clientUri += "?client_id=" + byClientId.getClientId() + "&response_type=code&client_name=" + URLEncoder.encode(byClientId.getClientName(), UTF_8.toString());
                if (!byClientId.getRedirectUris().isEmpty()) {
                    //TODO NE E LI PO_DOBRE DA IMA SAMO EDIN redirect_uri
                    clientUri += "&redirect_uri=" + StringUtils.join(byClientId.getRedirectUris(), " ");
                }
            }
            authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(clientUri);
        } else {
            authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginUri);
        }
        authenticationEntryPoint.commence(request, response, authException);
    }
}
