package co.id.btpn.web.monitoring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

	private static final Logger logger = LoggerFactory.getLogger(ContainerMonitoringApplication.class);


	
	public static void main(String[] args) {

		System.setProperty("kubernetes.trust.certificates", "true");


		

		SpringApplication.run(ContainerMonitoringApplication.class, args);

	}

	@Bean
	public LayoutDialect layoutDialect() {
		return new LayoutDialect();
		
	}

}
