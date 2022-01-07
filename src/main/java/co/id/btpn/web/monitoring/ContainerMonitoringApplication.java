package co.id.btpn.web.monitoring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import nz.net.ultraq.thymeleaf.LayoutDialect;

/**
 *
 * @author Ferry Fadly
 */
@SpringBootApplication
public class ContainerMonitoringApplication {

	
	public static void main(String[] args) {

		System.setProperty("kubernetes.trust.certificates", "true");


		

		SpringApplication.run(ContainerMonitoringApplication.class, args);

	}

	@Bean
	public LayoutDialect layoutDialect() {
		return new LayoutDialect();
		
	}

}
