package bg.mvr.dcis.oauth2.config.security;

import bg.mvr.dcis.access.AccessRequestBuilder;
import bg.mvr.dkis.accesssoap.AccessResponse;
import bg.mvr.dkis.accesssoap.Activity;
import bg.mvr.dkis.accesssoap.Subsystem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.ws.client.core.WebServiceTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private WebServiceTemplate webServiceTemplate;

    @Value("${subsystem.codes}")
    private String[] subsystems;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String user=authentication.getName();
        String password=authentication.getCredentials().toString();
        AccessResponse access = (AccessResponse) webServiceTemplate.marshalSendAndReceive((new AccessRequestBuilder().createAccessActivity(user, password, Arrays.asList(subsystems), "")));
        if (access.getResponse().getHead().getResult().getResultCode().equals("200")) {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            access.getResponse().getBody().getSubsystems().getSubsystem().forEach((Subsystem subsystem) -> {
                subsystem.getActivities().getActivity().forEach((Activity activity) -> {
                    authorities.add(new SimpleGrantedAuthority(activity.getActivityAbbr().trim()));
                });
            });
            return new UsernamePasswordAuthenticationToken(user,password,authorities);
        }else{
           throw new BadCredentialsException(access.getResponse().getHead().getResult().getResultTxt());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
