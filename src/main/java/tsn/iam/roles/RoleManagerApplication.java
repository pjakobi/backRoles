package tsn.iam.roles;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication(scanBasePackages={"tsn.iam.roles"})
public class RoleManagerApplication {
	public static void main(String[] args) { SpringApplication.run(RoleManagerApplication.class, args);	}
}