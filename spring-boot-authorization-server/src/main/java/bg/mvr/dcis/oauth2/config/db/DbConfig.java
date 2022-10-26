package bg.mvr.dcis.oauth2.config.db;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@Configuration
public class DbConfig {
    @Autowired
    private Environment env;

    @Bean(name = {"nips"})
    DataSource getDataSource() {
        HikariDataSource hikariDataSource = new HikariDataSource();
        hikariDataSource.setDriverClassName(this.env.getRequiredProperty("oauth.driverClassName"));
        hikariDataSource.setJdbcUrl(this.env.getRequiredProperty("oauth.url"));
        hikariDataSource.setUsername(this.env.getRequiredProperty("oauth.user"));
        hikariDataSource.setPassword(this.env.getRequiredProperty("oauth.password"));
        hikariDataSource.setConnectionTimeout(Long.parseLong(this.env.getRequiredProperty("oauth.hikari.connection-timeout")));
        hikariDataSource.setMaximumPoolSize(Integer.parseInt(this.env.getRequiredProperty("oauth.hikari.maximum-pool-size")));
        hikariDataSource.setIdleTimeout(Long.parseLong(this.env.getRequiredProperty("oauth.hikari.idle-timeout")));
        hikariDataSource.setMaxLifetime(Long.parseLong(this.env.getRequiredProperty("oauth.hikari.max-lifetime")));
        hikariDataSource.setMinimumIdle(Integer.parseInt(this.env.getRequiredProperty("oauth.hikari.minimum-idle")));
        return hikariDataSource;
    }
    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource){
       return new JdbcTemplate(dataSource);
    }
}
