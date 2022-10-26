package bg.mvr.dcis.oauth2.config.access;

import bg.mvr.dkis.accesssoap.AccessRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.soap.security.support.TrustManagersFactoryBean;
import org.springframework.ws.transport.http.HttpsUrlConnectionMessageSender;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
public class WebServiceTemplateConfig {

    @Value("${client.default-uri}")
    private String defaultUri;

    @Value("${client.ssl.keystore-path}")
    private Resource keystorePath;

    @Value("${client.ssl.keystore-password}")
    private String keystorePassword;


    @Bean
    public WebServiceTemplate webServiceTemplate() throws Exception {
        WebServiceTemplate webServiceTemplate = new WebServiceTemplate();
        Jaxb2Marshaller jaxb2Marshaller = new Jaxb2Marshaller();
        jaxb2Marshaller.setContextPath(AccessRequest.class.getPackage().getName());
        webServiceTemplate.setMarshaller(jaxb2Marshaller);
        webServiceTemplate.setUnmarshaller(jaxb2Marshaller);
        webServiceTemplate.setDefaultUri(defaultUri);
        webServiceTemplate.setMessageSender(httpsUrlConnectionMessageSender());
        return webServiceTemplate;
    }

    @Bean
    public HttpsUrlConnectionMessageSender httpsUrlConnectionMessageSender() throws Exception {
        HttpsUrlConnectionMessageSender httpsUrlConnectionMessageSender = new HttpsUrlConnectionMessageSender();
        httpsUrlConnectionMessageSender.setTrustManagers(trustManagersFactoryBean().getObject());
        return httpsUrlConnectionMessageSender;
    }

    @Bean
    public KeyStore keyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream keyStoreStrem = keystorePath.getInputStream()) {
            keyStore.load(keyStoreStrem, keystorePassword.toCharArray());
        }
        return keyStore;
    }


    @Bean
    public TrustManagersFactoryBean trustManagersFactoryBean() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        TrustManagersFactoryBean trustManagersFactoryBean = new TrustManagersFactoryBean();
        trustManagersFactoryBean.setKeyStore(keyStore());
        return trustManagersFactoryBean;
    }
}
