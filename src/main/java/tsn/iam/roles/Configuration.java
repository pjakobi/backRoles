package tsn.iam.roles;

import org.springframework.context.annotation.Bean;


public class Configuration {
	@Bean
	public SpifDir mySpifDir() { return new SpifDir(); }
}
