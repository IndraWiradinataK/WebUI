
package co.id.btpn.web.containerMonitoring;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.FormLoginRequestBuilder;
import org.springframework.test.web.servlet.MockMvc;

import co.id.btpn.web.monitoring.ContainerMonitoringApplication;

/**
 *
 * @author Ferry Fadly
 */
@SpringBootTest(classes = ContainerMonitoringApplication.class)
@AutoConfigureMockMvc
public class AuthenticatingLdapApplicationTests {
	@Autowired
	private MockMvc mockMvc;


	// @Test
	// public void loginWithValidUserThenAuthenticated3() throws Exception {
	// 	FormLoginRequestBuilder login = formLogin()
	// 		.user("user")
	// 		.password("password");

	// 	mockMvc.perform(login)
	// 		.andExpect(authenticated());
	// }
	

}
