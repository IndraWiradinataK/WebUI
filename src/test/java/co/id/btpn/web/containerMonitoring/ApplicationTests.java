
package co.id.btpn.web.containerMonitoring;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;

import org.evosuite.runtime.mock.java.time.MockInstant;
import org.evosuite.runtime.mock.java.util.MockDate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.FormLoginRequestBuilder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.*;

import co.id.btpn.web.monitoring.ContainerMonitoringApplication;
import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.model.CustomRuleFalco;
import co.id.btpn.web.monitoring.model.Role;
import co.id.btpn.web.monitoring.model.Userapp;
import co.id.btpn.web.monitoring.model.image.Annotations;
import co.id.btpn.web.monitoring.model.image.Image;
import co.id.btpn.web.monitoring.model.image.ImageContent;
import co.id.btpn.web.monitoring.model.image.ImageDetail;
import co.id.btpn.web.monitoring.model.image.ImagePostScan;
import co.id.btpn.web.monitoring.model.image.Metadata;
import co.id.btpn.web.monitoring.model.image.Registry;
import co.id.btpn.web.monitoring.model.policy.anchore.BlacklistedImage;
import co.id.btpn.web.monitoring.model.policy.anchore.Item;
import co.id.btpn.web.monitoring.model.policy.anchore.Mapping;
import co.id.btpn.web.monitoring.model.policy.anchore.Param;
import co.id.btpn.web.monitoring.model.policy.anchore.Policies;
import co.id.btpn.web.monitoring.model.policy.anchore.Policy;
import co.id.btpn.web.monitoring.model.policy.anchore.Policybundle;
import co.id.btpn.web.monitoring.model.policy.anchore.Rule;
import co.id.btpn.web.monitoring.model.policy.anchore.Whitelist;
import co.id.btpn.web.monitoring.model.policy.anchore.WhitelistedImage;
import co.id.btpn.web.monitoring.repository.RoleRepository;
import co.id.btpn.web.monitoring.repository.UserappRepository;
import co.id.btpn.web.monitoring.service.RoleService;
import co.id.btpn.web.monitoring.service.UserappService;
import co.id.btpn.web.monitoring.util.Util;
import io.florianlopes.spring.test.web.servlet.request.MockMvcRequestBuilderUtils;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static  org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import static org.evosuite.runtime.EvoAssertions.*;

import static org.junit.Assert.*;

import javax.naming.InvalidNameException;


import co.id.btpn.web.monitoring.model.policy.anchore.Param;
import co.id.btpn.web.monitoring.service.OpenshiftClientService;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ConfigMapList;
import io.fabric8.kubernetes.api.model.NamespaceBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.fabric8.openshift.client.OpenShiftClient;
import io.fabric8.openshift.client.server.mock.*;

import com.fasterxml.jackson.databind.ObjectMapper;


/**
 *
 * @author Ferry Fadly
 */


// properties = {  "spring.datasource.url=dburl","spring.datasource.username=dbuname","spring.datasource.password=dbpwd" }
// properties = {  "spring.ldap.urls=ldapurl","spring.ldap.base=ldapbase","spring.ldap.username=ldapuname","spring.ldap.password=ldappwd","ldap.base.dn.search=search","ldap.base.dn.search.filter=filter1","ldap.base.dn.search.filter2=filter2" }
// properties = {  "anchore.username=anchoreusername","anchore.password=anchorepassword","anchore.url=anchoreurl" }
// properties = {  "falco.username=falcousername","falco.password=falcopass","falco.url=falcourl" }
@SpringBootTest(classes = ContainerMonitoringApplication.class)
@EnableOpenShiftMockClient (crud = true)
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApplicationTests {
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	UserappService userappService;

	@Autowired
	UserappRepository userappRepository;

    @Autowired
	RoleService roleService;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
    OpenshiftClientService openshiftClientService;

	@Autowired
	private Util util;

    static OpenShiftMockServer server;
    static OpenShiftClient client;

	private String uName;
	private String uCN;
	private Boolean uLName;

	@Value("${falco.config.namespace}")
    private String fNameSpace;

	@Value("${kubernetes.namespace}")
    private String kNameSpace;


	@Value("${spring.ldap.username}")
    private String ldapUname;

	@Value("${spring.ldap.password}")
    private String ldapPass;


    @BeforeAll
    void init() {

        java.lang.System.setProperty(Config.KUBERNETES_MASTER_SYSTEM_PROPERTY,client.getConfiguration().getMasterUrl());
        java.lang.System.setProperty(Config.KUBERNETES_TRUST_CERT_SYSTEM_PROPERTY,"true");
        java.lang.System.setProperty(Config.KUBERNETES_AUTH_TRYKUBECONFIG_SYSTEM_PROPERTY, "false");
        java.lang.System.setProperty(Config.KUBERNETES_AUTH_TRYSERVICEACCOUNT_SYSTEM_PROPERTY, "false");
       // java.lang.System.setProperty(Config.KUBERNETES_HTTP2_DISABLE, "true");
        java.lang.System.setProperty(Config.KUBERNETES_NAMESPACE_SYSTEM_PROPERTY, "consec-dev"); // (4)

       

        client.namespaces().createOrReplace(
            new NamespaceBuilder().withNewMetadata().withName("consec-dev").addToLabels("this", "rocks").endMetadata().build()
        );

        client.namespaces().createOrReplace(
            new NamespaceBuilder().withNewMetadata().withName("consec-dev").addToLabels("this", "rocks").endMetadata().build()
        );

        

        java.util.Map <String,String> configMapData = new java.util.HashMap<>();
        configMapData.put("mail-options.incl", "test");

        ConfigMap newConfigMap = new ConfigMapBuilder().withNewMetadata()
            .withName("mail-options")
            .withNamespace("consec-dev")
            .addToLabels("app", "falco")
            .endMetadata()
            .addToData(configMapData)
            .build();
    
        client.configMaps().inNamespace("consec-dev").createOrReplace(newConfigMap);


 
        configMapData = new java.util.HashMap<>();
     
        configMapData.put("mailRecipient-CM.conf",  "test mailRecipient-CM.conf");
    
        newConfigMap = new ConfigMapBuilder().withNewMetadata()
            .withName("mail-recipient-list")
            .withNamespace("consec-dev")
            .endMetadata()
            .addToData(configMapData)
            .build();

        client.configMaps().inNamespace("consec-dev").createOrReplace(newConfigMap);


        configMapData = new java.util.HashMap<>();
     
        configMapData.put("falco_rules.local.yaml",  "test falco_rules.local.yaml");
    
        newConfigMap = new ConfigMapBuilder().withNewMetadata()
            .withName("falco")
            .withNamespace("consec-dev")
            .endMetadata()
            .addToData(configMapData)
            .build();

        client.configMaps().inNamespace("consec-dev").createOrReplace(newConfigMap);

        openshiftClientService.setConnection(client);

 

    }


	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void util() throws InvalidNameException {
		 uName = util.getLoggedUserName();
		 uCN = util.getLoggedCN();
		 uLName = util.isUserLoggedIn();

		 assertThat(uName).isEqualTo("admin");
		 assertThat(uCN).isEqualTo("");
		 assertThat(uLName).isEqualTo(Boolean.TRUE);
	}

	@Test
	@WithMockUser(username = "anonymousUser")
	void utilFalse() throws InvalidNameException {
		uName = util.getLoggedUserName();
		 uCN = util.getLoggedCN();
		 uLName = util.isUserLoggedIn();


		assertThat(uName).isEqualTo("anonymousUser");
		assertThat(uCN).isEqualTo("");
		assertThat(uLName).isEqualTo(Boolean.FALSE);
	}

	@Test
	void test0()  throws Throwable  {
		// Undeclared exception!
		try { 
			util.isUserLoggedIn();
		
		} catch(NullPointerException e) {
		   //
		   // org/springframework/security/core/context/SecurityContextHolder
		   //
		   verifyException("co.id.btpn.web.monitoring.util.Util", e);
		}
	}
  
	@Test
	void test1()  throws Throwable  {
		// Undeclared exception!
		try { 
		  util.getLoggedUserName();
		
		} catch(NullPointerException e) {
		   //
		   // org/springframework/security/core/context/SecurityContextHolder
		   //
		   verifyException("co.id.btpn.web.monitoring.util.Util", e);
		}
	}
  
	@Test
	void test2()  throws Throwable  {
		try { 
			util.getLoggedCN();
		
		} catch(NullPointerException e) {
		   //
		   // org/springframework/security/core/context/SecurityContextHolder
		   //
		   verifyException("co.id.btpn.web.monitoring.util.Util", e);
		}
	}



	@Test
	void main() {
		ContainerMonitoringApplication.main(new String[] {});
	}


	
	

	@Test
	void rootEndpoint() throws Exception {

		mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	void loginEndpoint() throws Exception {

		mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

	// in memory user 
	// @Test
	// void loginWithValidUserThenAuthenticated() throws Exception {
	// 	FormLoginRequestBuilder login = formLogin()
	// 		.user("user")
	// 		.password("password");

	// 	mockMvc.perform(login)
	// 		.andExpect(authenticated());
	// }


	// @Test
    // void loginWithValidUserThenAuthenticatedLdap() throws Exception {
    //     FormLoginRequestBuilder login = formLogin()
    //         .user("jhon")
    //         .password("secret");

    //     mockMvc.perform(login)
    //         .andExpect(authenticated().withUsername("jhon"));
    // }

    @Test
    void loginWithInvalidUserThenUnauthenticated() throws Exception {
        FormLoginRequestBuilder login = formLogin()
            .user("invalid")
            .password("invalidpassword");

        mockMvc.perform(login)
            .andExpect(unauthenticated());
    }



	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void dashboardEndpoint() throws Exception {
		
		mockMvc.perform(get("/dashboard")).andExpect(status().isOk());
	}

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void testscanregistryadd() throws Exception {
		
		mockMvc.perform(get("/scanregistryadd")).andExpect(status().isOk());
	}
	

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void scanondemandindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/scanondemandindex")).andExpect(status().isOk());
	}

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void servicestatusindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/servicestatusindex")).andExpect(status().isOk());
	}


	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void scanregistryindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/scanregistryindex")).andExpect(status().isOk());
	}

	
	
	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void policyanchoreindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/policyanchoreindex")).andExpect(status().isOk());
	}


	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void configfalcoindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/configfalcoindex")).andExpect(status().isOk());
		mockMvc.perform(get("/configfalcoedit?id=falco_rules.local.yaml")).andExpect(status().isOk());
	}

	
	




	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void userlogindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/userlogindex")).andExpect(status().isOk());
	}

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void userindexEndpoint() throws Exception {
		
		mockMvc.perform(get("/userappindex"))
		.andExpect(status().isOk());;
	}

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void useraddEndpoint() throws Exception {
		
		mockMvc.perform(get("/userappadd"))
		.andExpect(status().isOk());
	}

	
    
    

	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testAddUser() throws Exception {

			

			HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
			CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
			String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			Long long0 = 1L;
			final co.id.btpn.web.monitoring.model.Role dtoRole =   new Role(long0, "");
			 Userapp  dto = new Userapp();
			
			dto.setActive(1);
			dto.setName("dummy");
			dto.setRoleId(dtoRole);
			dto.setCn("DUMMY_cn");


			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/userappadd", dto).param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("userappindex"));

			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/userappadd", dto).param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("userappindex"));

			List<Userapp>  dtoList = userappRepository.findByName("dummy");
 
			dto = dtoList.get(0);
			dto.setActive(1);
			dto.setName("dummy_EDIT");
			dto.setCn("DUMMY_cn_EDIT");
			dto.setCreatedBy("dummy_admin_EDIT");
			dto.setCreatedDate(null);
			dto.setModifiedBy("dummy_admin_EDIT");

			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/userappedit", dto).param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("userappindex"));	

			dto = new Userapp();
			dto.setActive(1);
			dto.setName("dummy_EDIT2");
			dto.setCn("DUMMY_cn_EDIT2");
			dto.setCreatedBy("dummy_admin_EDIT2");
			dto.setCreatedDate(null);
			dto.setRoleId(dtoRole);
			dto.setModifiedBy("dummy_admin_EDIT2");

			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/userappedit", dto).param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("userappindex"));	

	}



	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testDeleteUser() throws Exception {

			List <Userapp> appud1 = userappRepository.findByName("dummy_EDIT");
			

			System.out.println("user di delete >>> "+appud1.get(0).getId());

			mockMvc.perform(get("/userappedit?id="+appud1.get(0).getId())
			).andExpect(status().isOk());


			mockMvc.perform(get("/userappdelete?id="+appud1.get(0).getId())
			).andExpect(redirectedUrl("userappindex"));

			

            List <Userapp> appud2 = userappRepository.findByName("dummy_EDIT2");
			

			System.out.println("user di delete >>> "+appud2.get(0).getId());

			mockMvc.perform(get("/userappedit?id="+appud2.get(0).getId())
			).andExpect(status().isOk());


			mockMvc.perform(get("/userappdelete?id="+appud2.get(0).getId())
			).andExpect(redirectedUrl("userappindex"));

			mockMvc.perform(get("/userappdelete?id=0")
			).andExpect(redirectedUrl("userappindex"));



            List <Userapp> appud3 = userappRepository.findByName("dummy");
			

			System.out.println("user di delete >>> "+appud3.get(0).getId());

			mockMvc.perform(get("/userappedit?id="+appud3.get(0).getId())
			).andExpect(status().isOk());


			mockMvc.perform(get("/userappdelete?id="+appud3.get(0).getId())
			).andExpect(redirectedUrl("userappindex"));

			mockMvc.perform(get("/userappdelete?id=0")
			).andExpect(redirectedUrl("userappindex"));


			// roleRepository.deleteAll();
			// userappRepository.deleteAll();
			// Long long0 = 1L;
			// final co.id.btpn.web.monitoring.model.Role dtoRole =   new Role(long0, "ADMIN");
			// roleRepository.save(dtoRole);
			// Long long1 = 2L;
			// final co.id.btpn.web.monitoring.model.Role dtoRole2 =   new Role(long1, "USER");
			// roleRepository.save(dtoRole2);

			
	}


	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testAddRegistry() throws Exception {

			

			HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
			CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
			String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			Long long0 = 1L;
			final co.id.btpn.web.monitoring.model.Role dtoRole =   new Role(long0, "");
			Registry  dto = new Registry();
			
			dto.setRegistryName("docker.io/ffadly");
			dto.setRegistry("docker.io/ffadly");
			dto.setRegistryType("docker_v2");
			dto.setRegistryUser("ffadly");
			dto.setRegistryPass("Jakarta1!");
			dto.setRegistryVerify(false);


			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/scanregistryadd", dto).param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("scanregistryindex"));

			this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/scanregistryedit", dto)
			.param(csrfToken.getParameterName(), csrfToken.getToken())
			.param("rname", "docker.io/ffadly")
			.sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("scanregistryindex"));
			
			mockMvc.perform(get("/scanregistryedit?rname=docker.io/ffadly")
			).andExpect(status().isOk());

			mockMvc.perform(get("/scanregistrydelete?rname=docker.io/ffadly")
			).andExpect(redirectedUrl("scanregistryindex"));


	}

	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void imagealertindexEndpoint() throws Exception {

		HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
		CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
		String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

		
		mockMvc.perform(get("/imagealertindex")).andExpect(status().isOk());
	
		this.mockMvc.perform(post("/imagealertupdate")
		.accept(MediaType.APPLICATION_JSON)
		.param("id", "2")
		.param("actionId", "3")
		.param("enabled", "1")
		// .content("{\"id\":\"anchore_cis_1.13.0_base\",\"enabled\":\"true\"}")
		.contentType(MediaType.APPLICATION_JSON)
		.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
		.andExpect(status().isOk());
	

		this.mockMvc.perform(post("/runtimealertupdate")
		.accept(MediaType.APPLICATION_JSON)
		.param("name", "ImageScanNOTIFY")
		.param("enabled", "1")
		// .content("{\"id\":\"anchore_cis_1.13.0_base\",\"enabled\":\"true\"}")
		.contentType(MediaType.APPLICATION_JSON)
		.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
		.andExpect(status().isOk());

	}

	


	@Test
	@WithMockUser(username = "admin", roles  = "ADMIN")
	void emailconfigEndpoint() throws Exception {


		HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
		CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
		String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

		
		mockMvc.perform(get("/emailconfig?id=mailRecipient-CM.conf")).andExpect(status().isOk());

		ConfigMap cm =  client.configMaps().inNamespace(kNameSpace).withName("mail-recipient-list").get();
		java.util.Map<String,String> map = cm.getData();
		String email =map.get("mailRecipient-CM.conf");
		
		co.id.btpn.web.monitoring.model.policy.anchore.Param param = new co.id.btpn.web.monitoring.model.policy.anchore.Param();
		param.setName("mailRecipient-CM.conf");
		param.setValue(email);


		this.mockMvc.perform(MockMvcRequestBuilderUtils.postForm("/emailconfig", param)
			.param(csrfToken.getParameterName(), csrfToken.getToken())
			.sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("imagealertindex"));

	}


    public static String asJsonString(final Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testscandonDemand() throws Exception {


		HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
		CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
		String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

		ImagePostScan post = new ImagePostScan();
		post.setTag("docker.io/python:slim-buster");
			
		this.mockMvc.perform(post("/scanondemandadd")
		.accept(MediaType.APPLICATION_JSON)
		.param("tag", "docker.io/python:slim-buster")
		.content(asJsonString(post))
		.contentType(MediaType.APPLICATION_JSON)
		.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
		.andExpect(status().isOk());		
	}

	//login
	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testEditUserLogin() throws Exception {

			

			HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
			CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
			String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			this.mockMvc.perform(post("/login")
			.param("username", "admin")
			.param("password", "password")
			.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("/dashboard"));		
	}

	//login ldap 
	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testEditUserLoginLdap() throws Exception {



			HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
			CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
			String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			this.mockMvc.perform(post("/login")
			.param("username", ldapUname)
			.param("password", ldapPass)
			.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("/dashboard"));		
	}

	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testpolicyanchoreupdate() throws Exception {


		HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
		CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
		String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			
		this.mockMvc.perform(post("/policyanchoreupdate")
		.accept(MediaType.APPLICATION_JSON)
		.param("id", "default2")
		.param("enabled", "true")
		// .content("{\"id\":\"anchore_cis_1.13.0_base\",\"enabled\":\"true\"}")
		.contentType(MediaType.APPLICATION_JSON)
		.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
		.andExpect(status().isOk());		

		this.mockMvc.perform(post("/policyanchoreupdate")
		.accept(MediaType.APPLICATION_JSON)
		// .content("{\"id\":\"anchore-policy-warn\",\"enabled\":\"true\"}")
		.param("id", "anchore-policy-warn")
		.param("enabled", "true")
		.contentType(MediaType.APPLICATION_JSON)
		.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
		.andExpect(status().isOk());	


	}




	@Test
    @WithMockUser(username = "admin", roles  = "ADMIN")
    void testEditConfigFalco() throws Exception {

			
			ConfigMap cm =  client.configMaps().inNamespace(fNameSpace).withName("falco").get();
			java.util.Map<String,String> map = cm.getData();

			String content = map.get("falco_rules.local.yaml");

			HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
			CsrfToken csrfToken = httpSessionCsrfTokenRepository.generateToken(new MockHttpServletRequest());
			String TOKEN_ATTR_NAME = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";

			this.mockMvc.perform(post("/configfalcoedit")
			.param("name", "falco_rules.local.yaml")
			.param("value", content)
			.param(csrfToken.getParameterName(), csrfToken.getToken()).sessionAttr(TOKEN_ATTR_NAME, csrfToken))
			.andExpect(redirectedUrl("configfalcoindex"));		
	}

	// ============ OBJECT TEST ==================

	//Userapp Dto
	@Test
	void testuserAppDto00()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Role role0 = userapp0.getRoleId();
		assertNull(role0);
	}
  
	@Test
	void testuserAppDto01()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		String string0 = userapp0.getName();
		assertNull(string0);
	}
  
	@Test
	void testuserAppDto02()  throws Throwable  {
		Long long0 = 1080L;
		Date Date0 = new Date();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", 1, "", "", Date0, "", Date0, (Role) null);
		userapp0.getName();
		assertEquals(1, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto03()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", (-1782), "", "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", Date0, "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", Date0, role0);
		userapp0.getModifiedDate();
		assertEquals("", userapp0.getName());
		assertEquals((-1782), userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getModifiedBy());
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getCreatedBy());
		assertEquals("", userapp0.getCn());
	}
  
	@Test
	void testuserAppDto04()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		String string0 = userapp0.getModifiedBy();
		assertNull(string0);
	}
  
	@Test
	void testuserAppDto05()  throws Throwable  {
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp((Long) null, "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", 1, "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", "", Date0, "", Date0, role0);
		String string0 = userapp0.getModifiedBy();
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getName());
		assertEquals("", userapp0.getCreatedBy());
		assertEquals(1, userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getCn());
		assertEquals("", string0);
	}
  
	@Test
	void testuserAppDto06()  throws Throwable  {
		Long long0 = 1592L;
		Date Date0 = new Date((-530));
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", (-530), "", "`|/~@iQD", Date0, "", Date0, role0);
		userapp0.getId();
		assertEquals("`|/~@iQD", userapp0.getCreatedBy());
		assertEquals("", userapp0.getName());
		assertEquals((-530), userapp0.getActive());
		assertEquals("", userapp0.getModifiedBy());
		assertEquals("", userapp0.getCn());
	}
  
	@Test
	void testuserAppDto07()  throws Throwable  {
		Long long0 = (-1L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, ":`");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", 749, ":`", "", Date0, ":`", Date0, role0);
		userapp0.getId();
		assertEquals(":`", userapp0.getModifiedBy());
		assertEquals(749, userapp0.getActive());
		assertEquals(":`", userapp0.getCn());
		assertEquals("", userapp0.getName());
		assertEquals("", userapp0.getCreatedBy());
	}
  
	@Test
	void testuserAppDto08()  throws Throwable  {
		Long long0 = (-234L);
		Date Date0 = new Date();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", 4360, "9.%bfIw<1wr0?+M0", "9.%bfIw<1wr0?+M0", Date0, "co.id.btpn.web.monitoring.model.Role", Date0, (Role) null);
		userapp0.getCreatedDate();
		assertEquals(4360, userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getModifiedBy());
		assertEquals("", userapp0.getName());
		assertEquals("9.%bfIw<1wr0?+M0", userapp0.getCn());
		assertEquals("9.%bfIw<1wr0?+M0", userapp0.getCreatedBy());
	}
  
	@Test
	void testuserAppDto09()  throws Throwable  {
		Long long0 = 1482L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "i$-YM^l#i2<\"]", 2161, "i$-YM^l#i2<\"]", "i$-YM^l#i2<\"]", Date0, "^>P[c+.k[l.cv4sFu", Date0, role0);
		String string0 = userapp0.getCreatedBy();
		assertEquals("^>P[c+.k[l.cv4sFu", userapp0.getModifiedBy());
		assertEquals("i$-YM^l#i2<\"]", userapp0.getCn());
		assertEquals("i$-YM^l#i2<\"]", string0);
		assertEquals("i$-YM^l#i2<\"]", userapp0.getName());
		assertEquals(2161, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto10()  throws Throwable  {
		Long long0 = (-1L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, "+QGe");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "E<:sv1Ir1%=OYW33-7T", 3684, "+QGe", "", Date0, "z]2", Date0, role0);
		String string0 = userapp0.getCreatedBy();
		assertEquals("", string0);
		assertEquals(3684, userapp0.getActive());
		assertEquals("z]2", userapp0.getModifiedBy());
		assertEquals("E<:sv1Ir1%=OYW33-7T", userapp0.getName());
		assertEquals("+QGe", userapp0.getCn());
	}
  
	@Test
	void testuserAppDto11()  throws Throwable  {
		Long long0 = (-867L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, "co.id.btpn.web.monitoring.dto.co.id.btpn.web.monitoring.dto.Userapp");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "co.id.btpn.web.monitoring.dto.co.id.btpn.web.monitoring.dto.Userapp", 0, "&v Z5z:j-8(wK", "&v Z5z:j-8(wK", Date0, "&v Z5z:j-8(wK", Date0, role0);
		String string0 = userapp0.getCn();
		assertEquals("co.id.btpn.web.monitoring.dto.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getName());
		assertEquals(0, userapp0.getActive());
		assertEquals("&v Z5z:j-8(wK", string0);
		assertEquals("&v Z5z:j-8(wK", userapp0.getCreatedBy());
		assertEquals("&v Z5z:j-8(wK", userapp0.getModifiedBy());
	}
  
	@Test
	void testuserAppDto12()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setCn("");
		String string0 = userapp0.getCn();
		assertEquals("", string0);
	}
  
	@Test
	void testuserAppDto13()  throws Throwable  {
		Long long0 = 1L;
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "co.id.btpn.web.monitoring.model.Role", 359, "!F*4kpcYdLU", "Uz a04E(-Sa+", Date0, "?0J", Date0, role0);
		int int0 = userapp0.getActive();
		assertEquals(359, int0);
		assertEquals("?0J", userapp0.getModifiedBy());
		assertEquals("!F*4kpcYdLU", userapp0.getCn());
		assertEquals("Uz a04E(-Sa+", userapp0.getCreatedBy());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getName());
	}
  
	@Test
	void testuserAppDto14()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "", (-1782), "", "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", Date0, "co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", Date0, role0);
		int int0 = userapp0.getActive();
		assertEquals("", userapp0.getCn());
		assertEquals((-1782), int0);
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getModifiedBy());
		assertEquals("", userapp0.getName());
		assertEquals("co.id.btpn.web.monitoring.model.co.id.btpn.web.monitoring.dto.Userapp", userapp0.getCreatedBy());
	}
  
	@Test
	void testuserAppDto15()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		int int0 = userapp0.getActive();
		assertEquals(0, int0);
	}
  
	@Test
	void testuserAppDto16()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		userapp0.getRoleId();
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getName());
		assertEquals("D", userapp0.getModifiedBy());
		assertEquals("D", userapp0.getCn());
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
	}
  
	@Test
	void testuserAppDto17()  throws Throwable  {
		Long long0 = (-530L);
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "?4zl$B+7", 2853, "?4zl$B+7", "co.id.btpn.web.monitoring.model.Role", Date0, "?4zl$B+7", Date0, role0);
		userapp0.setCreatedDate(Date0);
		assertEquals("?4zl$B+7", userapp0.getName());
		assertEquals("?4zl$B+7", userapp0.getModifiedBy());
		assertEquals("?4zl$B+7", userapp0.getCn());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getCreatedBy());
		assertEquals(2853, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto18()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Date date0 = userapp0.getCreatedDate();
		assertNull(date0);
	}
  
	@Test
	void testuserAppDto19()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Role role0 = new Role();
		userapp0.setRoleId(role0);
		assertNull(userapp0.getModifiedBy());
	}
  
	@Test
	void testuserAppDto20()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		String string0 = userapp0.getName();
		assertEquals("D", string0);
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getModifiedBy());
		assertEquals("D", userapp0.getCn());
	}
  
	@Test
	void testuserAppDto21()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setCreatedBy((String) null);
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto22()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Date date0 = userapp0.getModifiedDate();
		assertNull(date0);
	}
  
	@Test
	void testuserAppDto23()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setModifiedBy("0|8% }`t^DKzGKHzk");
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto24()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		String string0 = userapp0.getCn();
		assertNull(string0);
	}
  
	@Test
	void testuserAppDto25()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setName("");
		assertNull(userapp0.getCn());
	}
  
	@Test
	void testuserAppDto26()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Long long0 = userapp0.getId();
		assertNull(long0);
	}
  
	@Test
	void testuserAppDto27()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role();
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		String string0 = userapp0.getModifiedBy();
		assertEquals("D", userapp0.getCn());
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getName());
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
		assertEquals("D", string0);
	}
  
	@Test
	void testuserAppDto28()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setModifiedDate((Date) null);
		assertNull(userapp0.getName());
	}
  
	@Test
	void testuserAppDto29()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		userapp0.setActive(0);
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void testuserAppDto30()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		Long long0 = 0L;
		userapp0.setId(long0);
		Long long1 = userapp0.getId();
		assertEquals(0L, (long)long1);
	}
  
	@Test
	void testuserAppDto31()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.Userapp userapp0 = new co.id.btpn.web.monitoring.dto.Userapp();
		String string0 = userapp0.getCreatedBy();
		assertNull(string0);
	}
	//Userapp Entity
	@Test
	void test00()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Role role0 = userapp0.getRoleId();
		assertNull(role0);
	}
  
	@Test
	void test01()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		String string0 = userapp0.getName();
		assertNull(string0);
	}
  
	@Test
	void test02()  throws Throwable  {
		Long long0 = 1080L;
		Date Date0 = new Date();
		Userapp userapp0 = new Userapp(long0, "", 1, "", "", Date0, "", Date0, (Role) null);
		userapp0.getName();
		assertEquals(1, userapp0.getActive());
	}
  
	@Test
	void test03()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		Userapp userapp0 = new Userapp(long0, "", (-1782), "", "co.id.btpn.web.monitoring.model.Userapp", Date0, "co.id.btpn.web.monitoring.model.Userapp", Date0, role0);
		userapp0.getModifiedDate();
		assertEquals("", userapp0.getName());
		assertEquals((-1782), userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getModifiedBy());
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getCreatedBy());
		assertEquals("", userapp0.getCn());
	}
  
	@Test
	void test04()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		String string0 = userapp0.getModifiedBy();
		assertNull(string0);
	}
  
	@Test
	void test05()  throws Throwable  {
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp((Long) null, "co.id.btpn.web.monitoring.model.Userapp", 1, "co.id.btpn.web.monitoring.model.Userapp", "", Date0, "", Date0, role0);
		String string0 = userapp0.getModifiedBy();
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getName());
		assertEquals("", userapp0.getCreatedBy());
		assertEquals(1, userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getCn());
		assertEquals("", string0);
	}
  
	@Test
	void test06()  throws Throwable  {
		Long long0 = 1592L;
		Date Date0 = new Date((-530));
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "", (-530), "", "`|/~@iQD", Date0, "", Date0, role0);
		userapp0.getId();
		assertEquals("`|/~@iQD", userapp0.getCreatedBy());
		assertEquals("", userapp0.getName());
		assertEquals((-530), userapp0.getActive());
		assertEquals("", userapp0.getModifiedBy());
		assertEquals("", userapp0.getCn());
	}
  
	@Test
	void test07()  throws Throwable  {
		Long long0 = (-1L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, ":`");
		Userapp userapp0 = new Userapp(long0, "", 749, ":`", "", Date0, ":`", Date0, role0);
		userapp0.getId();
		assertEquals(":`", userapp0.getModifiedBy());
		assertEquals(749, userapp0.getActive());
		assertEquals(":`", userapp0.getCn());
		assertEquals("", userapp0.getName());
		assertEquals("", userapp0.getCreatedBy());
	}
  
	@Test
	void test08()  throws Throwable  {
		Long long0 = (-234L);
		Date Date0 = new Date();
		Userapp userapp0 = new Userapp(long0, "", 4360, "9.%bfIw<1wr0?+M0", "9.%bfIw<1wr0?+M0", Date0, "co.id.btpn.web.monitoring.model.Role", Date0, (Role) null);
		userapp0.getCreatedDate();
		assertEquals(4360, userapp0.getActive());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getModifiedBy());
		assertEquals("", userapp0.getName());
		assertEquals("9.%bfIw<1wr0?+M0", userapp0.getCn());
		assertEquals("9.%bfIw<1wr0?+M0", userapp0.getCreatedBy());
	}
  
	@Test
	void test09()  throws Throwable  {
		Long long0 = 1482L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		Userapp userapp0 = new Userapp(long0, "i$-YM^l#i2<\"]", 2161, "i$-YM^l#i2<\"]", "i$-YM^l#i2<\"]", Date0, "^>P[c+.k[l.cv4sFu", Date0, role0);
		String string0 = userapp0.getCreatedBy();
		assertEquals("^>P[c+.k[l.cv4sFu", userapp0.getModifiedBy());
		assertEquals("i$-YM^l#i2<\"]", userapp0.getCn());
		assertEquals("i$-YM^l#i2<\"]", string0);
		assertEquals("i$-YM^l#i2<\"]", userapp0.getName());
		assertEquals(2161, userapp0.getActive());
	}
  
	@Test
	void test10()  throws Throwable  {
		Long long0 = (-1L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, "+QGe");
		Userapp userapp0 = new Userapp(long0, "E<:sv1Ir1%=OYW33-7T", 3684, "+QGe", "", Date0, "z]2", Date0, role0);
		String string0 = userapp0.getCreatedBy();
		assertEquals("", string0);
		assertEquals(3684, userapp0.getActive());
		assertEquals("z]2", userapp0.getModifiedBy());
		assertEquals("E<:sv1Ir1%=OYW33-7T", userapp0.getName());
		assertEquals("+QGe", userapp0.getCn());
	}
  
	@Test
	void test11()  throws Throwable  {
		Long long0 = (-867L);
		Date Date0 = new Date();
		Role role0 = new Role(long0, "co.id.btpn.web.monitoring.dto.Userapp");
		Userapp userapp0 = new Userapp(long0, "co.id.btpn.web.monitoring.dto.Userapp", 0, "&v Z5z:j-8(wK", "&v Z5z:j-8(wK", Date0, "&v Z5z:j-8(wK", Date0, role0);
		String string0 = userapp0.getCn();
		assertEquals("co.id.btpn.web.monitoring.dto.Userapp", userapp0.getName());
		assertEquals(0, userapp0.getActive());
		assertEquals("&v Z5z:j-8(wK", string0);
		assertEquals("&v Z5z:j-8(wK", userapp0.getCreatedBy());
		assertEquals("&v Z5z:j-8(wK", userapp0.getModifiedBy());
	}
  
	@Test
	void test12()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setCn("");
		String string0 = userapp0.getCn();
		assertEquals("", string0);
	}
  
	@Test
	void test13()  throws Throwable  {
		Long long0 = 1L;
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "co.id.btpn.web.monitoring.model.Role", 359, "!F*4kpcYdLU", "Uz a04E(-Sa+", Date0, "?0J", Date0, role0);
		int int0 = userapp0.getActive();
		assertEquals(359, int0);
		assertEquals("?0J", userapp0.getModifiedBy());
		assertEquals("!F*4kpcYdLU", userapp0.getCn());
		assertEquals("Uz a04E(-Sa+", userapp0.getCreatedBy());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getName());
	}
  
	@Test
	void test14()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role(long0, "");
		Userapp userapp0 = new Userapp(long0, "", (-1782), "", "co.id.btpn.web.monitoring.model.Userapp", Date0, "co.id.btpn.web.monitoring.model.Userapp", Date0, role0);
		int int0 = userapp0.getActive();
		assertEquals("", userapp0.getCn());
		assertEquals((-1782), int0);
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getModifiedBy());
		assertEquals("", userapp0.getName());
		assertEquals("co.id.btpn.web.monitoring.model.Userapp", userapp0.getCreatedBy());
	}
  
	@Test
	void test15()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		int int0 = userapp0.getActive();
		assertEquals(0, int0);
	}
  
	@Test
	void test16()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		userapp0.getRoleId();
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getName());
		assertEquals("D", userapp0.getModifiedBy());
		assertEquals("D", userapp0.getCn());
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
	}
  
	@Test
	void test17()  throws Throwable  {
		Long long0 = (-530L);
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "?4zl$B+7", 2853, "?4zl$B+7", "co.id.btpn.web.monitoring.model.Role", Date0, "?4zl$B+7", Date0, role0);
		userapp0.setCreatedDate(Date0);
		assertEquals("?4zl$B+7", userapp0.getName());
		assertEquals("?4zl$B+7", userapp0.getModifiedBy());
		assertEquals("?4zl$B+7", userapp0.getCn());
		assertEquals("co.id.btpn.web.monitoring.model.Role", userapp0.getCreatedBy());
		assertEquals(2853, userapp0.getActive());
	}
  
	@Test
	void test18()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Date date0 = userapp0.getCreatedDate();
		assertNull(date0);
	}
  
	@Test
	void test19()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Role role0 = new Role();
		userapp0.setRoleId(role0);
		assertNull(userapp0.getModifiedBy());
	}
  
	@Test
	void test20()  throws Throwable  {
		Long long0 = 0L;
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		String string0 = userapp0.getName();
		assertEquals("D", string0);
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getModifiedBy());
		assertEquals("D", userapp0.getCn());
	}
  
	@Test
	void test21()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setCreatedBy((String) null);
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void test22()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Date date0 = userapp0.getModifiedDate();
		assertNull(date0);
	}
  
	@Test
	void test23()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setModifiedBy("0|8% }`t^DKzGKHzk");
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void test24()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		String string0 = userapp0.getCn();
		assertNull(string0);
	}
  
	@Test
	void test25()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setName("");
		assertNull(userapp0.getCn());
	}
  
	@Test
	void test26()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Long long0 = userapp0.getId();
		assertNull(long0);
	}
  
	@Test
	void test27()  throws Throwable  {
		Long long0 = (0L);
		Date Date0 = new Date();
		Role role0 = new Role();
		Userapp userapp0 = new Userapp(long0, "D", (-677), "D", "VaF,Jr3T44It!0!q{", Date0, "D", Date0, role0);
		String string0 = userapp0.getModifiedBy();
		assertEquals("D", userapp0.getCn());
		assertEquals((-677), userapp0.getActive());
		assertEquals("D", userapp0.getName());
		assertEquals("VaF,Jr3T44It!0!q{", userapp0.getCreatedBy());
		assertEquals("D", string0);
	}
  
	@Test
	void test28()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setModifiedDate((Date) null);
		assertNull(userapp0.getName());
	}
  
	@Test
	void test29()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		userapp0.setActive(0);
		assertEquals(0, userapp0.getActive());
	}
  
	@Test
	void test30()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		Long long0 = 0L;
		userapp0.setId(long0);
		Long long1 = userapp0.getId();
		assertEquals(0L, (long)long1);
	}
  
	@Test
	void test31()  throws Throwable  {
		Userapp userapp0 = new Userapp();
		String string0 = userapp0.getCreatedBy();
		assertNull(string0);
	}
	
	//user log DTO
@Test
	void testUserLogDto00()  throws Throwable  {
		Long long0 = (-1L);
		MockDate mockDate0 = new MockDate();
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "xM&#e", "xM&#e", mockDate0, "xM&#e");
		String string0 = userLog0.getName();
		assertEquals("xM&#e", string0);
	}
  
	@Test
	void testUserLogDto01()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "", "", mockDate0, "");
		String string0 = userLog0.getName();
		assertEquals("", string0);
	}
  
	@Test
	void testUserLogDto02()  throws Throwable  {
		Long long0 = 0L;
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "", "", (Date) null, "");
		Long long1 = userLog0.getId();
		assertEquals(0L, (long)long1);
	}
  
	@Test
	void testUserLogDto03()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		Long long0 = 1L;
		userLog0.setId(long0);
		Long long1 = userLog0.getId();
		assertEquals(1L, (long)long1);
	}
  
	@Test
	void testUserLogDto04()  throws Throwable  {
		Long long0 = (-14L);
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "x^~QX^2", "x^~QX^2", (Date) null, "j(V!N<3`|z]");
		userLog0.getId();
		assertEquals("x^~QX^2", userLog0.getName());
		assertEquals("x^~QX^2", userLog0.getActivity());
		assertEquals("j(V!N<3`|z]", userLog0.getCn());
	}
  
	@Test
	void testUserLogDto05()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate((-2649), (-2649), 0);
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "evX6X]R", "evX6X]R", mockDate0, "evX6X]R");
		String string0 = userLog0.getCn();
		assertEquals("evX6X]R", string0);
	}
  
	@Test
	void testUserLogDto06()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "4aq6.g8cQzoq7i[{Xz", "4aq6.g8cQzoq7i[{Xz", mockDate0, "");
		String string0 = userLog0.getCn();
		assertEquals("4aq6.g8cQzoq7i[{Xz", userLog0.getActivity());
		assertEquals("", string0);
		assertEquals("4aq6.g8cQzoq7i[{Xz", userLog0.getName());
	}
  
	@Test
	void testUserLogDto07()  throws Throwable  {
		Long long0 = 0L;
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "", "", (Date) null, "");
		userLog0.setActivity("2OX&LS/me");
		String string0 = userLog0.getActivity();
		assertEquals("2OX&LS/me", string0);
	}
  
	@Test
	void testUserLogDto08()  throws Throwable  {
		Instant instant0 = MockInstant.now();
		Date date0 = Date.from(instant0);
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog((Long) null, "*U=|nryK^y", "", date0, "");
		String string0 = userLog0.getActivity();
		assertEquals("*U=|nryK^y", userLog0.getName());
		assertEquals("", userLog0.getCn());
		assertEquals("", string0);
	}
  
	@Test
	void testUserLogDto09()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		String string0 = userLog0.getName();
		assertNull(string0);
	}
  
	@Test
	void testUserLogDto10()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		String string0 = userLog0.getCn();
		assertNull(string0);
	}
  
	@Test
	void testUserLogDto11()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		userLog0.setName("Asia/Jakarta");
		assertNull(userLog0.getActivity());
	}
  
	@Test
	void testUserLogDto12()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog(long0, "\"C*", "\"C*", mockDate0, "\"C*");
		userLog0.setCn("\"C*");
		assertEquals("\"C*", userLog0.getName());
	}
  
	@Test
	void testUserLogDto13()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		MockDate mockDate0 = new MockDate(141, 141, 141, (-1), (-1), (-1));
		userLog0.setLogDate(mockDate0);
		Date date0 = userLog0.getLogDate();
		assertEquals(date0.toString(), date0.toString());
	}
  
	@Test
	void testUserLogDto14()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		Date date0 = userLog0.getLogDate();
		assertNull(date0);
	}
  
	@Test
	void testUserLogDto15()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		Long long0 = userLog0.getId();
		assertNull(long0);
	}
  
	@Test
	void testUserLogDto16()  throws Throwable  {
		co.id.btpn.web.monitoring.dto.UserLog userLog0 = new co.id.btpn.web.monitoring.dto.UserLog();
		String string0 = userLog0.getActivity();
		assertNull(string0);
	}
	//user log 
	
	@Test
	void testUserLog00()  throws Throwable  {
		Long long0 = (-1L);
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "xM&#e", "xM&#e", mockDate0, "xM&#e");
		String string0 = userLog0.getName();
		assertEquals("xM&#e", string0);
	}
  
	@Test
	void testUserLog01()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "", "", mockDate0, "");
		String string0 = userLog0.getName();
		assertEquals("", string0);
	}
  
	@Test
	void testUserLog02()  throws Throwable  {
		Long long0 = 0L;
		UserLog userLog0 = new UserLog(long0, "", "", (Date) null, "");
		Long long1 = userLog0.getId();
		assertEquals(0L, (long)long1);
	}
  
	@Test
	void testUserLog03()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		Long long0 = 1L;
		userLog0.setId(long0);
		Long long1 = userLog0.getId();
		assertEquals(1L, (long)long1);
	}
  
	@Test
	void testUserLog04()  throws Throwable  {
		Long long0 = (-14L);
		UserLog userLog0 = new UserLog(long0, "x^~QX^2", "x^~QX^2", (Date) null, "j(V!N<3`|z]");
		userLog0.getId();
		assertEquals("x^~QX^2", userLog0.getName());
		assertEquals("x^~QX^2", userLog0.getActivity());
		assertEquals("j(V!N<3`|z]", userLog0.getCn());
	}
  
	@Test
	void testUserLog05()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate((-2649), (-2649), 0);
		UserLog userLog0 = new UserLog(long0, "evX6X]R", "evX6X]R", mockDate0, "evX6X]R");
		String string0 = userLog0.getCn();
		assertEquals("evX6X]R", string0);
	}
  
	@Test
	void testUserLog06()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "4aq6.g8cQzoq7i[{Xz", "4aq6.g8cQzoq7i[{Xz", mockDate0, "");
		String string0 = userLog0.getCn();
		assertEquals("4aq6.g8cQzoq7i[{Xz", userLog0.getActivity());
		assertEquals("", string0);
		assertEquals("4aq6.g8cQzoq7i[{Xz", userLog0.getName());
	}
  
	@Test
	void testUserLog07()  throws Throwable  {
		Long long0 = 0L;
		UserLog userLog0 = new UserLog(long0, "", "", (Date) null, "");
		userLog0.setActivity("2OX&LS/me");
		String string0 = userLog0.getActivity();
		assertEquals("2OX&LS/me", string0);
	}
  
	@Test
	void testUserLog08()  throws Throwable  {
		Instant instant0 = MockInstant.now();
		Date date0 = Date.from(instant0);
		UserLog userLog0 = new UserLog((Long) null, "*U=|nryK^y", "", date0, "");
		String string0 = userLog0.getActivity();
		assertEquals("*U=|nryK^y", userLog0.getName());
		assertEquals("", userLog0.getCn());
		assertEquals("", string0);
	}
  
	@Test
	void testUserLog09()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		String string0 = userLog0.getName();
		assertNull(string0);
	}
  
	@Test
	void testUserLog10()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		String string0 = userLog0.getCn();
		assertNull(string0);
	}
  
	@Test
	void testUserLog11()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		userLog0.setName("Asia/Jakarta");
		assertNull(userLog0.getActivity());
	}
  
	@Test
	void testUserLog12()  throws Throwable  {
		Long long0 = 0L;
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "\"C*", "\"C*", mockDate0, "\"C*");
		userLog0.setCn("\"C*");
		assertEquals("\"C*", userLog0.getName());
	}
  
	@Test
	void testUserLog13()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		MockDate mockDate0 = new MockDate(141, 141, 141, (-1), (-1), (-1));
		userLog0.setLogDate(mockDate0);
		Date date0 = userLog0.getLogDate();
		assertEquals( date0.toString(), date0.toString());
	}
  
	@Test
	void testUserLog14()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		Date date0 = userLog0.getLogDate();
		assertNull(date0);
	}
  
	@Test
	void testUserLog15()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		Long long0 = userLog0.getId();
		assertNull(long0);
	}
  
	@Test
	void testUserLog16()  throws Throwable  {
		UserLog userLog0 = new UserLog();
		String string0 = userLog0.getActivity();
		assertNull(string0);
	}

	@Test
	void testUserLog17()  throws Throwable  {
		Long long0 = (-1L);
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "xM&#e", "xM&#e", mockDate0, "xM&#e");
		assertEquals(mockDate0, userLog0.getLogDate());
	}
	
	@Test
	void testUserLog18()  throws Throwable  {
		Long long0 = (-1L);
		MockDate mockDate0 = new MockDate();
		UserLog userLog0 = new UserLog(long0, "xM&#e", "xM&#e", mockDate0, "xM&#e");
		assertEquals(mockDate0, userLog0.getLogDate());
	}

	@Test
	void testUserLog19()  throws Throwable  {
		Long long0 = (-1L);
		UserLog userLog0 = new UserLog(long0, "xM&#e", "xM&#e", null, "xM&#e");
		userLog0.setId(long0);
		assertEquals(null, userLog0.getInstanceLogDate());
	}

	//custom rule falco 


	@Test
	void testcustomrulefalco00()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		Integer integer0 = new Integer(0);
		customRuleFalco0.setEnabled(integer0);
		assertNull(customRuleFalco0.getActionName());
	}
  
	@Test
	void testcustomrulefalco01()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		customRuleFalco0.setRuleName("u%o6>wAC7{Bjw");
		String string0 = customRuleFalco0.getRuleName();
		assertEquals("u%o6>wAC7{Bjw", string0);
	}
  
	@Test
	void testcustomrulefalco02()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("", (Integer) null, (Integer) null, "");
		String string0 = customRuleFalco0.getRuleName();
		assertEquals("", string0);
	}
  
	@Test
	void testcustomrulefalco03()  throws Throwable  {
		Integer integer0 = new Integer((-1391));
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("Wqp@bLW3tM)edNwDN@{", integer0, integer0, "Wqp@bLW3tM)edNwDN@{");
		Integer integer1 = new Integer(0);
		customRuleFalco0.setId(integer1);
		customRuleFalco0.getId();
		assertEquals(0, (int)customRuleFalco0.getId());
	}
  
	@Test
	void testcustomrulefalco04()  throws Throwable  {
		Integer integer0 = new Integer(796);
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("P3C9Uv", integer0, integer0, "P3C9Uv");
		Integer integer1 = customRuleFalco0.getId();
		assertEquals(796, (int)integer1);
	}
  
	@Test
	void testcustomrulefalco05()  throws Throwable  {
		Integer integer0 = new Integer((-1));
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("5B`qtKb]FiO3.`H", integer0, integer0, "5B`qtKb]FiO3.`H");
		Integer integer1 = customRuleFalco0.getId();
		assertEquals((-1), (int)integer1);
	}
  
	@Test
	void testcustomrulefalco06()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		Integer integer0 = new Integer(0);
		customRuleFalco0.enabled = integer0;
		Integer integer1 = customRuleFalco0.getEnabled();
		assertEquals(0, (int)integer1);
	}
  
	@Test
	void testcustomrulefalco07()  throws Throwable  {
		Integer integer0 = new Integer(796);
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("P3C9Uv", integer0, integer0, "P3C9Uv");
		Integer integer1 = customRuleFalco0.getEnabled();
		assertEquals(796, (int)integer1);
	}
  
	@Test
	void testcustomrulefalco08()  throws Throwable  {
		Integer integer0 = new Integer((-1391));
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco("Wqp@bLW3tM)edNwDN@{", integer0, integer0, "Wqp@bLW3tM)edNwDN@{");
		Integer integer1 = customRuleFalco0.getEnabled();
		assertEquals((-1391), (int)integer1);
	}
  
	@Test
	void testcustomrulefalco09()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		customRuleFalco0.setActionName("9S;JdV'=}R)*n!C?");
		String string0 = customRuleFalco0.getActionName();
		assertEquals("9S;JdV'=}R)*n!C?", string0);
	}
  
	@Test
	void testcustomrulefalco10()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		Integer integer0 = customRuleFalco0.getId();
		assertNull(integer0);
	}
  
	@Test
	void testcustomrulefalco11()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		String string0 = customRuleFalco0.getActionName();
		assertNull(string0);
	}
  
	@Test
	void testcustomrulefalco12()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		customRuleFalco0.setActionName("");
		String string0 = customRuleFalco0.getActionName();
		assertEquals("", string0);
	}
  
	@Test
	void testcustomrulefalco13()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		String string0 = customRuleFalco0.getRuleName();
		assertNull(string0);
	}
  
	@Test
	void testcustomrulefalco14()  throws Throwable  {
		CustomRuleFalco customRuleFalco0 = new CustomRuleFalco();
		Integer integer0 = customRuleFalco0.getEnabled();
		assertNull(integer0);
	}

	// Image 

	@Test
  void testimage00()  throws Throwable  {
      Image image0 = new Image();
      image0.setCreatedAt("");
      // Undeclared exception!
      try { 
        image0.getInstanceAnalyzedAtDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text '' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testimage01()  throws Throwable  {
      Image image0 = new Image();
      Annotations annotations0 = new Annotations();
	  annotations0.setOrigins("webui");
      image0.setAnnotations(annotations0);
      assertNull(image0.getAnalyzedAt());
  }

  @Test
  void testimage02()  throws Throwable  {
      Image image0 = new Image();
      image0.userId = "W%1GMK3^kp,[3(g^";
      String string0 = image0.getUserId();
      assertEquals("W%1GMK3^kp,[3(g^", string0);
  }

  @Test
  void testimage03()  throws Throwable  {
      Image image0 = new Image();
      image0.setUserId("");
      String string0 = image0.getUserId();
      assertEquals("", string0);
  }

  @Test
  void testimage04()  throws Throwable  {
      Image image0 = new Image();
      image0.setParentDigest("qetv1_zvd");
      String string0 = image0.getParentDigest();
      assertEquals("qetv1_zvd", string0);
  }

  @Test
  void testimage05()  throws Throwable  {
      Image image0 = new Image();
      image0.setParentDigest("");
      String string0 = image0.getParentDigest();
      assertEquals("", string0);
  }

  @Test
  void testimage06()  throws Throwable  {
      Image image0 = new Image();
      image0.setLastUpdated("");
      String string0 = image0.getLastUpdated();
      assertEquals("", string0);
  }

  @Test
  void testimage07()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageType("co.id.btpn.web.monitoring.model.image.Image");
      String string0 = image0.getImageType();
      assertEquals("co.id.btpn.web.monitoring.model.image.Image", string0);
  }

  @Test
  void testimage08()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageType("");
      String string0 = image0.getImageType();
      assertEquals("", string0);
  }

  @Test
  void testimage09()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageStatus("co.id.btpn.web.monitoring.model.image.ImageContent");
      String string0 = image0.getImageStatus();
      assertEquals("co.id.btpn.web.monitoring.model.image.ImageContent", string0);
  }

  @Test
  void testimage10()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageStatus("");
      String string0 = image0.getImageStatus();
      assertEquals("", string0);
  }

  @Test
  void testimage11()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageDigest("qetv1_zvd");
      String string0 = image0.getImageDigest();
      assertEquals("qetv1_zvd", string0);
  }

  @Test
  void testimage12()  throws Throwable  {
      Image image0 = new Image();
      image0.setImageDigest("");
      String string0 = image0.getImageDigest();
      assertEquals("", string0);
  }

  @Test
  void testimage13()  throws Throwable  {
      Image image0 = new Image();
      LinkedList<ImageDetail> linkedList0 = new LinkedList<ImageDetail>();
      image0.setImageDetail(linkedList0);
      List<ImageDetail> list0 = image0.getImageDetail();
      assertEquals(0, list0.size());
  }

  @Test
  void testimage14()  throws Throwable  {
      Image image0 = new Image();
      LinkedList<ImageDetail> linkedList0 = new LinkedList<ImageDetail>();
      ImageDetail imageDetail0 = new ImageDetail();
      linkedList0.add(imageDetail0);
      image0.setImageDetail(linkedList0);
      List<ImageDetail> list0 = image0.getImageDetail();
      assertEquals(1, list0.size());
  }

  @Test
  void testimage15()  throws Throwable  {
      Image image0 = new Image();
      ImageContent imageContent0 = new ImageContent();
      image0.setImageContent(imageContent0);
      ImageContent imageContent1 = image0.getImageContent();
      assertSame(imageContent1, imageContent0);
  }

  @Test
  void testimage16()  throws Throwable  {
      Image image0 = new Image();
      image0.setCreatedAt("qetv1_zvd");
      String string0 = image0.getCreatedAt();
      assertEquals("qetv1_zvd", string0);
  }

  @Test
  void testimage17()  throws Throwable  {
      Image image0 = new Image();
      Annotations annotations0 = new Annotations();
      image0.annotations = annotations0;
      Annotations annotations1 = image0.getAnnotations();
      assertSame(annotations1, annotations0);
  }

  @Test
  void testimage18()  throws Throwable  {
      Image image0 = new Image();
      image0.setAnalyzedAt("n<UAL1Oj'Qx}Ey(N");
      String string0 = image0.getAnalyzedAt();
      assertEquals("n<UAL1Oj'Qx}Ey(N", string0);
  }

  @Test
  void testimage19()  throws Throwable  {
      Image image0 = new Image();
      image0.setAnalyzedAt("");
      String string0 = image0.getAnalyzedAt();
      assertEquals("", string0);
  }

  @Test
  void testimage20()  throws Throwable  {
      Image image0 = new Image();
      image0.setAnalysisStatus("4(4c/\"^mnN+wT;K");
      String string0 = image0.getAnalysisStatus();
      assertEquals("4(4c/\"^mnN+wT;K", string0);
  }

  @Test
  void testimage21()  throws Throwable  {
      Image image0 = new Image();
      image0.setAnalysisStatus("");
      String string0 = image0.getAnalysisStatus();
      assertEquals("", string0);
  }

  @Test
  void testimage22()  throws Throwable  {
      Image image0 = new Image();
      image0.setAnalyzedAt("&2ZjE^zF_B");
      // Undeclared exception!
      try { 
        image0.getInstanceAnalyzedAtDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text '&2ZjE^zF_B' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testimage23()  throws Throwable  {
      Image image0 = new Image();
      // Undeclared exception!
      try { 
        image0.getInstanceAnalyzedAtDate();
      
      } catch(NullPointerException e) {
         //
         // text
         //
         verifyException("java.util.Objects", e);
      }
  }

  @Test
  void testimage24()  throws Throwable  {
      Image image0 = new Image();
      List<ImageDetail> list0 = image0.getImageDetail();
      assertNull(list0);
  }

  @Test
  void testimage25()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getAnalysisStatus();
      assertNull(string0);
  }

  @Test
  void testimage26()  throws Throwable  {
      Image image0 = new Image();
      ImageContent imageContent0 = image0.getImageContent();
      assertNull(imageContent0);
  }

  @Test
  void testimage27()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getImageDigest();
      assertNull(string0);
  }

  @Test
  void testimage28()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getUserId();
      assertNull(string0);
  }

  @Test
  void testimage29()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getImageType();
      assertNull(string0);
  }

  @Test
  void testimage30()  throws Throwable  {
      Image image0 = new Image();
      image0.setCreatedAt("");
      String string0 = image0.getCreatedAt();
      assertEquals("", string0);
  }

  @Test
  void testimage31()  throws Throwable  {
      Image image0 = new Image();
      Annotations annotations0 = image0.getAnnotations();
      assertNull(annotations0);
  }

  @Test
  void testimage32()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getImageStatus();
      assertNull(string0);
  }

  @Test
  void testimage33()  throws Throwable  {
      Image image0 = new Image();
      image0.setLastUpdated("^<1RUvLD2");
      String string0 = image0.getLastUpdated();
      assertEquals("^<1RUvLD2", string0);
  }

  @Test
  void testimage34()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getParentDigest();
      assertNull(string0);
  }

  @Test
  void testimage35()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getLastUpdated();
      assertNull(string0);
  }

  @Test
  void testimage36()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getAnalyzedAt();
      assertNull(string0);
  }

  @Test
  void testimage37()  throws Throwable  {
      Image image0 = new Image();
      String string0 = image0.getCreatedAt();
      assertNull(string0);
  }

  @Test
  void testimage38()  throws Throwable  {
      Image image0 = new Image();
      image0.setCreatedAt("2018-11-30T18:35:24.00Z");
	  image0.setLastUpdated("^<1RUvLD2");
      assertNotNull(image0.getInstanceAnalyzedAtDate());
  }
  @Test
  void testimage39()  throws Throwable  {
      Image image0 = new Image();
	  image0.setAnalyzedAt("2018-11-30T18:35:24.00Z");
      assertNotNull(image0.getInstanceAnalyzedAtDate());
  }

  // image post 

  @Test
  void testimagepost0()  throws Throwable  {
      ImagePostScan imagePostScan0 = new ImagePostScan();
      imagePostScan0.tag = "";
      imagePostScan0.tag = "Gm(Az4R";
      String string0 = imagePostScan0.getTag();
      assertEquals("Gm(Az4R", string0);
  }

  @Test
  void testimagepost1()  throws Throwable  {
      ImagePostScan imagePostScan0 = new ImagePostScan();
      Annotations annotations0 = new Annotations();
      imagePostScan0.setAnnotations(annotations0);
      Annotations annotations1 = imagePostScan0.getAnnotations();
      assertNull(annotations1.getOrigins());
  }

  @Test
  void testimagepost2()  throws Throwable  {
      ImagePostScan imagePostScan0 = new ImagePostScan();
      Annotations annotations0 = imagePostScan0.getAnnotations();
      assertNull(annotations0);
  }

  @Test
  void testimagepost3()  throws Throwable  {
      ImagePostScan imagePostScan0 = new ImagePostScan();
      String string0 = imagePostScan0.getTag();
      assertNull(string0);
  }

  @Test
  void testimagepost4()  throws Throwable  {
      ImagePostScan imagePostScan0 = new ImagePostScan();
      imagePostScan0.setTag("");
      String string0 = imagePostScan0.getTag();
      assertEquals("", string0);
  }

  // metadata

  @Test
  void testmetadata0()  throws Throwable  {
      Metadata metadata0 = new Metadata();
      
  }

  // registry 

  @Test
  void testregistry00()  throws Throwable  {
      Registry registry0 = new Registry();
      Boolean boolean0 = Boolean.valueOf("-\"D~q]CaOq6wv5");
      registry0.setRegistryVerify(boolean0);
      assertNull(registry0.getRegistryName());
  }

  @Test
  void testregistry01()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setUserId("");
      assertNull(registry0.getRegistryName());
  }

  @Test
  void testregistry02()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setRegistryType("");
      assertNull(registry0.getCreatedAt());
  }

  @Test
  void testregistry03()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.userId = "8L";
      String string0 = registry0.getUserId();
      assertEquals("8L", string0);
  }

  @Test
  void testregistry04()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.userId = "";
      String string0 = registry0.getUserId();
      assertEquals("", string0);
  }

  @Test
  void testregistry05()  throws Throwable  {
      Registry registry0 = new Registry();
      Boolean boolean0 = Boolean.TRUE;
      registry0.registryVerify = boolean0;
      Boolean boolean1 = registry0.getRegistryVerify();
      assertTrue(boolean1);
  }

  @Test
  void testregistry06()  throws Throwable  {
      Registry registry0 = new Registry();
      Boolean boolean0 = Boolean.FALSE;
      registry0.registryVerify = boolean0;
      Boolean boolean1 = registry0.getRegistryVerify();
      assertFalse(boolean1);
  }

  @Test
  void testregistry07()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registryUser = "Asia/Jakarta";
      String string0 = registry0.getRegistryUser();
      assertEquals("Asia/Jakarta", string0);
  }

  @Test
  void testregistry08()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setRegistryUser("");
      String string0 = registry0.getRegistryUser();
      assertEquals("", string0);
  }

  @Test
  void testregistry09()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registryType = "M(Q";
      String string0 = registry0.getRegistryType();
      assertEquals("M(Q", string0);
  }

  @Test
  void testregistry10()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registryType = "";
      String string0 = registry0.getRegistryType();
      assertEquals("", string0);
  }

  @Test
  void testregistry11()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registryPass = "Zg(1yvT1`#";
      String string0 = registry0.getRegistryPass();
      assertEquals("Zg(1yvT1`#", string0);
  }

  @Test
  void testregistry12()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setRegistryPass("");
      String string0 = registry0.getRegistryPass();
      assertEquals("", string0);
  }

  @Test
  void testregistry13()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setRegistryName("co.id.btpn.web.monitoring.model.image.Registry");
      String string0 = registry0.getRegistryName();
      assertEquals("co.id.btpn.web.monitoring.model.image.Registry", string0);
  }

  @Test
  void testregistry14()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registryName = "";
      String string0 = registry0.getRegistryName();
      assertEquals("", string0);
  }

  @Test
  void testregistry15()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registry = "8(";
      String string0 = registry0.getRegistry();
      assertEquals("8(", string0);
  }

  @Test
  void testregistry16()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.registry = "";
      String string0 = registry0.getRegistry();
      assertEquals("", string0);
  }

  @Test
  void testregistry17()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setLastUpated("N;`J[6|x\"|hdbxFY?");
      String string0 = registry0.getLastUpated();
      assertEquals("N;`J[6|x\"|hdbxFY?", string0);
  }

  @Test
  void testregistry18()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.lastUpated = "";
      String string0 = registry0.getLastUpated();
      assertEquals("", string0);
  }

  @Test
  void testregistry19()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setCreatedAt(")dm95&aXgrwK");
      String string0 = registry0.getCreatedAt();
      assertEquals(")dm95&aXgrwK", string0);
  }

  @Test
  void testregistry20()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setCreatedAt("");
      String string0 = registry0.getCreatedAt();
      assertEquals("", string0);
  }

  @Test
  void testregistry21()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.lastUpated = "n$|}P9iq;]$";
      // Undeclared exception!
      try { 
        registry0.getInstanceLastUpatedDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text 'n$|}P9iq;]$' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testregistry22()  throws Throwable  {
      Registry registry0 = new Registry();
      ZonedDateTime zonedDateTime0 = registry0.getInstanceLastUpatedDate();
      assertNull(zonedDateTime0);
  }

  @Test
  void testregistry23()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setCreatedAt(")dm95&aXgrwK");
      // Undeclared exception!
      try { 
        registry0.getInstanceCreatedAtDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text ')dm95&aXgrwK' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testregistry24()  throws Throwable  {
      Registry registry0 = new Registry();
      ZonedDateTime zonedDateTime0 = registry0.getInstanceCreatedAtDate();
      assertNull(zonedDateTime0);
  }

  @Test
  void testregistry25()  throws Throwable  {
      Registry registry0 = new Registry();
      registry0.setRegistry("");
      assertNull(registry0.getCreatedAt());
  }

  @Test
  void testregistry26()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getRegistryName();
      assertNull(string0);
  }

  @Test
  void testregistry27()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getCreatedAt();
      assertNull(string0);
  }

  @Test
  void testregistry28()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getLastUpated();
      assertNull(string0);
  }

  @Test
  void testregistry29()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getRegistry();
      assertNull(string0);
  }

  @Test
  void testregistry30()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getRegistryType();
      assertNull(string0);
  }

  @Test
  void testregistry31()  throws Throwable  {
      Registry registry0 = new Registry();
      Boolean boolean0 = registry0.getRegistryVerify();
      assertNull(boolean0);
  }

  @Test
  void testregistry32()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getUserId();
      assertNull(string0);
  }

  @Test
  void testregistry33()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getRegistryPass();
      assertNull(string0);
  }

  @Test
  void testregistry34()  throws Throwable  {
      Registry registry0 = new Registry();
      String string0 = registry0.getRegistryUser();
      assertNull(string0);
  }

  @Test
  void testregistry35()  throws Throwable  {
      Registry registry0 = new Registry();
	  registry0.setLastUpated("2018-11-30T18:35:24.00Z");
      ZonedDateTime zonedDateTime0 = registry0.getInstanceLastUpatedDate();
      assertNotNull(zonedDateTime0);
  }

  // policies


  @Test
  void testpolicies00()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setUserId("or<:Xxi:Nr;aj;A|e?");
      String string0 = policies0.getUserId();
      assertEquals("or<:Xxi:Nr;aj;A|e?", string0);
  }

  @Test
  void testpolicies01()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.userId = "";
      String string0 = policies0.getUserId();
      assertEquals("", string0);
  }

  @Test
  void testpolicies02()  throws Throwable  {
      Policies policies0 = new Policies();
      Policybundle policybundle0 = new Policybundle();
      policies0.setPolicybundle(policybundle0);
      Policybundle policybundle1 = policies0.getPolicybundle();
      assertNull(policybundle1.getComment());
  }

  @Test
  void testpolicies03()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setPolicySource("{*Rs(5*r");
      String string0 = policies0.getPolicySource();
      assertEquals("{*Rs(5*r", string0);
  }

  @Test
  void testpolicies04()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setPolicySource("");
      String string0 = policies0.getPolicySource();
      assertEquals("", string0);
  }

  @Test
  void testpolicies05()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.policyId = "yBJ";
      String string0 = policies0.getPolicyId();
      assertEquals("yBJ", string0);
  }

  @Test
  void testpolicies06()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setName("yBJ");
      String string0 = policies0.getName();
      assertEquals("yBJ", string0);
  }

  @Test
  void testpolicies07()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.name = "";
      String string0 = policies0.getName();
      assertEquals("", string0);
  }

  @Test
  void testpolicies08()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setLastUpdated("u}1");
      String string0 = policies0.getLastUpdated();
      assertEquals("u}1", string0);
  }

  @Test
  void testpolicies09()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setDescription("A(>Q;V$R]");
      String string0 = policies0.getDescription();
      assertEquals("A(>Q;V$R]", string0);
  }

  @Test
  void testpolicies10()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setCreatedAt("co.id.btpn.web.monitoring.model.policy.anchore.BlacklistedImage");
      String string0 = policies0.getCreatedAt();
      assertEquals("co.id.btpn.web.monitoring.model.policy.anchore.BlacklistedImage", string0);
  }

  @Test
  void testpolicies11()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setCreatedAt("");
      String string0 = policies0.getCreatedAt();
      assertEquals("", string0);
  }

  @Test
  void testpolicies12()  throws Throwable  {
      Policies policies0 = new Policies();
      Boolean boolean0 = Boolean.TRUE;
      policies0.setActive(boolean0);
      Boolean boolean1 = policies0.getActive();
      assertTrue(boolean1);
  }

  @Test
  void testpolicies13()  throws Throwable  {
      Policies policies0 = new Policies();
      Boolean boolean0 = Boolean.FALSE;
      policies0.active = boolean0;
      Boolean boolean1 = policies0.getActive();
      assertFalse(boolean1);
  }

  @Test
  void testpolicies14()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.createdAt = "co.id.btpn.web.monitoring.model.policy.anchore.Policies";
      // Undeclared exception!
      try { 
        policies0.getInstanceCreatedAtDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text 'co.id.btpn.web.monitoring.model.policy.anchore.Policies' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testpolicies15()  throws Throwable  {
      Policies policies0 = new Policies();
      ZonedDateTime zonedDateTime0 = policies0.getInstanceCreatedAtDate();
      assertNull(zonedDateTime0);
  }

  @Test
  void testpolicies16()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setLastUpdated("H|UrQ");
      // Undeclared exception!
      try { 
        policies0.getInstanceLastUpdatedDate();
      
      } catch(DateTimeParseException e) {
         //
         // Text 'H|UrQ' could not be parsed at index 0
         //
         verifyException("java.time.format.DateTimeFormatter", e);
      }
  }

  @Test
  void testpolicies17()  throws Throwable  {
      Policies policies0 = new Policies();
      ZonedDateTime zonedDateTime0 = policies0.getInstanceLastUpdatedDate();
      assertNull(zonedDateTime0);
  }

  @Test
  void testpolicies18()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setPolicyId("");
      String string0 = policies0.getPolicyId();
      assertEquals("", string0);
  }

  @Test
  void testpolicies19()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getPolicySource();
      assertNull(string0);
  }

  @Test
  void testpolicies20()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getDescription();
      assertNull(string0);
  }

  @Test
  void testpolicies21()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setDescription("");
      String string0 = policies0.getDescription();
      assertEquals("", string0);
  }

  @Test
  void testpolicies22()  throws Throwable  {
      Policies policies0 = new Policies();
      Policybundle policybundle0 = policies0.getPolicybundle();
      assertNull(policybundle0);
  }

  @Test
  void testpolicies23()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getCreatedAt();
      assertNull(string0);
  }

  @Test
  void testpolicies24()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getUserId();
      assertNull(string0);
  }

  @Test
  void testpolicies25()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getPolicyId();
      assertNull(string0);
  }

  @Test
  void testpolicies26()  throws Throwable  {
      Policies policies0 = new Policies();
      policies0.setLastUpdated("");
      String string0 = policies0.getLastUpdated();
      assertEquals("", string0);
  }

  @Test
  void testpolicies27()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getName();
      assertNull(string0);
  }

  @Test
  void testpolicies28()  throws Throwable  {
      Policies policies0 = new Policies();
      String string0 = policies0.getLastUpdated();
      assertNull(string0);
  }

  @Test
  void testpolicies29()  throws Throwable  {
      Policies policies0 = new Policies();
      Boolean boolean0 = policies0.getActive();
      assertNull(boolean0);
  }

  //policy bundle 


  @Test
  void testpolicybundle00()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Mapping> linkedList0 = new LinkedList<Mapping>();
      policybundle0.setMappings(linkedList0);
      assertNull(policybundle0.getName());
  }

  @Test
  void testpolicybundle01()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Whitelist> linkedList0 = new LinkedList<Whitelist>();
      policybundle0.whitelists = (List<Whitelist>) linkedList0;
      List<Whitelist> list0 = policybundle0.getWhitelists();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testpolicybundle02()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Whitelist> linkedList0 = new LinkedList<Whitelist>();
      Whitelist whitelist0 = new Whitelist();
      linkedList0.add(whitelist0);
      policybundle0.setWhitelists(linkedList0);
      List<Whitelist> list0 = policybundle0.getWhitelists();
      assertTrue(list0.contains(whitelist0));
  }

  @Test
  void testpolicybundle03()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<WhitelistedImage> linkedList0 = new LinkedList<WhitelistedImage>();
      policybundle0.setWhitelistedImages(linkedList0);
      List<WhitelistedImage> list0 = policybundle0.getWhitelistedImages();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testpolicybundle04()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<WhitelistedImage> linkedList0 = new LinkedList<WhitelistedImage>();
      WhitelistedImage whitelistedImage0 = new WhitelistedImage();
      linkedList0.add(whitelistedImage0);
      policybundle0.setWhitelistedImages(linkedList0);
      List<WhitelistedImage> list0 = policybundle0.getWhitelistedImages();
      assertEquals(1, list0.size());
  }

  @Test
  void testpolicybundle05()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.version = "V7r{wZ:<m##RM";
      String string0 = policybundle0.getVersion();
      assertEquals("V7r{wZ:<m##RM", string0);
  }

  @Test
  void testpolicybundle06()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setVersion("");
      String string0 = policybundle0.getVersion();
      assertEquals("", string0);
  }

  @Test
  void testpolicybundle07()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Policy> linkedList0 = new LinkedList<Policy>();
      policybundle0.policies = (List<Policy>) linkedList0;
      List<Policy> list0 = policybundle0.getPolicies();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testpolicybundle08()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Policy> linkedList0 = new LinkedList<Policy>();
      Policy policy0 = new Policy();
      linkedList0.add(policy0);
      policybundle0.setPolicies(linkedList0);
      List<Policy> list0 = policybundle0.getPolicies();
      assertEquals(1, list0.size());
  }

  @Test
  void testpolicybundle09()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setName("^O%=UrQlCe`Rn");
      String string0 = policybundle0.getName();
      assertEquals("^O%=UrQlCe`Rn", string0);
  }

  @Test
  void testpolicybundle10()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.name = "";
      String string0 = policybundle0.getName();
      assertEquals("", string0);
  }

  @Test
  void testpolicybundle11()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Mapping> linkedList0 = new LinkedList<Mapping>();
      policybundle0.mappings = (List<Mapping>) linkedList0;
      List<Mapping> list0 = policybundle0.getMappings();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testpolicybundle12()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<Mapping> linkedList0 = new LinkedList<Mapping>();
      policybundle0.mappings = (List<Mapping>) linkedList0;
      Mapping mapping0 = new Mapping();
      linkedList0.add(mapping0);
      List<Mapping> list0 = policybundle0.getMappings();
      assertEquals(1, list0.size());
  }

  @Test
  void testpolicybundle13()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setId("q1k");
      String string0 = policybundle0.getId();
      assertEquals("q1k", string0);
  }

  @Test
  void testpolicybundle14()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setId("");
      String string0 = policybundle0.getId();
      assertEquals("", string0);
  }

  @Test
  void testpolicybundle15()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setComment("d(OVi`5roTLxwC");
      String string0 = policybundle0.getComment();
      assertEquals("d(OVi`5roTLxwC", string0);
  }

  @Test
  void testpolicybundle16()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      policybundle0.setComment("");
      String string0 = policybundle0.getComment();
      assertEquals("", string0);
  }

  @Test
  void testpolicybundle17()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<BlacklistedImage> linkedList0 = new LinkedList<BlacklistedImage>();
      policybundle0.setBlacklistedImages(linkedList0);
      List<BlacklistedImage> list0 = policybundle0.getBlacklistedImages();
      assertEquals(0, list0.size());
  }

  @Test
  void testpolicybundle18()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      LinkedList<BlacklistedImage> linkedList0 = new LinkedList<BlacklistedImage>();
      policybundle0.blacklistedImages = (List<BlacklistedImage>) linkedList0;
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      linkedList0.add(blacklistedImage0);
      List<BlacklistedImage> list0 = policybundle0.getBlacklistedImages();
      assertTrue(list0.contains(blacklistedImage0));
  }

  @Test
  void testpolicybundle19()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      List<Mapping> list0 = policybundle0.getMappings();
      assertNull(list0);
  }

  @Test
  void testpolicybundle20()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      List<Whitelist> list0 = policybundle0.getWhitelists();
      assertNull(list0);
  }

  @Test
  void testpolicybundle21()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      String string0 = policybundle0.getVersion();
      assertNull(string0);
  }

  @Test
  void testpolicybundle22()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      List<WhitelistedImage> list0 = policybundle0.getWhitelistedImages();
      assertNull(list0);
  }

  @Test
  void testpolicybundle23()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      String string0 = policybundle0.getId();
      assertNull(string0);
  }

  @Test
  void testpolicybundle24()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      List<Policy> list0 = policybundle0.getPolicies();
      assertNull(list0);
  }

  @Test
  void testpolicybundle25()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      String string0 = policybundle0.getName();
      assertNull(string0);
  }

  @Test
  void testpolicybundle26()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      String string0 = policybundle0.getComment();
      assertNull(string0);
  }

  @Test
  void testpolicybundle27()  throws Throwable  {
      Policybundle policybundle0 = new Policybundle();
      List<BlacklistedImage> list0 = policybundle0.getBlacklistedImages();
      assertNull(list0);
  }

  // mapping

  @Test
  void testmapping00()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      LinkedList<String> linkedList0 = new LinkedList<String>();
      mapping0.whitelistIds = (List<String>) linkedList0;
      List<String> list0 = mapping0.getWhitelistIds();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testmapping01()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      LinkedList<String> linkedList0 = new LinkedList<String>();
      linkedList0.add("co.id.btpn.web.monitoring.model.policy.anchore.Mapping");
      mapping0.setWhitelistIds(linkedList0);
      List<String> list0 = mapping0.getWhitelistIds();
      assertEquals(1, list0.size());
  }

  @Test
  void testmapping02()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setRepository("-!z8WYG");
      String string0 = mapping0.getRepository();
      assertEquals("-!z8WYG", string0);
  }

  @Test
  void testmapping03()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setRepository("");
      String string0 = mapping0.getRepository();
      assertEquals("", string0);
  }

  @Test
  void testmapping04()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.registry = "UF0KsuJ7*t)n5Cst";
      String string0 = mapping0.getRegistry();
      assertEquals("UF0KsuJ7*t)n5Cst", string0);
  }

  @Test
  void testmapping05()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setRegistry("");
      String string0 = mapping0.getRegistry();
      assertEquals("", string0);
  }

  @Test
  void testmapping06()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      LinkedList<String> linkedList0 = new LinkedList<String>();
      mapping0.whitelistIds = (List<String>) linkedList0;
      mapping0.setPolicyIds(mapping0.whitelistIds);
      List<String> list0 = mapping0.getPolicyIds();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testmapping07()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      LinkedList<String> linkedList0 = new LinkedList<String>();
      linkedList0.offerFirst("");
      mapping0.setPolicyIds(linkedList0);
      List<String> list0 = mapping0.getPolicyIds();
      assertEquals(1, list0.size());
  }

  @Test
  void testmapping08()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setPolicyId("rBH");
      String string0 = mapping0.getPolicyId();
      assertEquals("rBH", string0);
  }

  @Test
  void testmapping09()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setPolicyId("");
      String string0 = mapping0.getPolicyId();
      assertEquals("", string0);
  }

  @Test
  void testmapping10()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setName("-!z8WYG");
      String string0 = mapping0.getName();
      assertEquals("-!z8WYG", string0);
  }

  @Test
  void testmapping11()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setName("");
      String string0 = mapping0.getName();
      assertEquals("", string0);
  }

  @Test
  void testmapping12()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      co.id.btpn.web.monitoring.model.policy.anchore.Image image0 = new co.id.btpn.web.monitoring.model.policy.anchore.Image();
	  image0.setValue("uName");
	  image0.setType("Image Type");
	  mapping0.setImage(image0);
      co.id.btpn.web.monitoring.model.policy.anchore.Image image1 = mapping0.getImage();
      assertSame(image1, image0);
	  assertSame(image0.getValue(), "uName");
	  assertSame(image0.getType(), "Image Type");
  }

  @Test
  void testmapping13()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setId("i{Z)-9m?hTt");
      String string0 = mapping0.getId();
      assertEquals("i{Z)-9m?hTt", string0);
  }

  @Test
  void testmapping14()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      mapping0.setId("");
      String string0 = mapping0.getId();
      assertEquals("", string0);
  }

  @Test
  void testmapping15()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      String string0 = mapping0.getId();
      assertNull(string0);
  }

  @Test
  void testmapping16()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      co.id.btpn.web.monitoring.model.policy.anchore.Image image0 = mapping0.getImage();
      assertNull(image0);
  }

  @Test
  void testmapping17()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      String string0 = mapping0.getRepository();
      assertNull(string0);
  }

  @Test
  void testmapping18()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      List<String> list0 = mapping0.getPolicyIds();
      assertNull(list0);
  }

  @Test
  void testmapping19()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      String string0 = mapping0.getRegistry();
      assertNull(string0);
  }

  @Test
  void testmapping20()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      String string0 = mapping0.getPolicyId();
      assertNull(string0);
  }

  @Test
  void testmapping21()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      String string0 = mapping0.getName();
      assertNull(string0);
  }

  @Test
  void testmapping22()  throws Throwable  {
      Mapping mapping0 = new Mapping();
      List<String> list0 = mapping0.getWhitelistIds();
      assertNull(list0);
  }

  // Blacklisted


  @Test
  void testblacklisted00()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setRepository("2SMFz.=/I>D$mQ&u");
      String string0 = blacklistedImage0.getRepository();
      assertEquals("2SMFz.=/I>D$mQ&u", string0);
  }

  @Test
  void testblacklisted01()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setRepository("");
      String string0 = blacklistedImage0.getRepository();
      assertEquals("", string0);
  }

  @Test
  void testblacklisted02()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.registry = "J={#e7)g{)gTyZUGr0";
      String string0 = blacklistedImage0.getRegistry();
      assertEquals("J={#e7)g{)gTyZUGr0", string0);
  }

  @Test
  void testblacklisted03()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setName("_-5M.%K?Km;");
      String string0 = blacklistedImage0.getName();
      assertEquals("_-5M.%K?Km;", string0);
  }

  @Test
  void testblacklisted04()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.name = "";
      String string0 = blacklistedImage0.getName();
      assertEquals("", string0);
  }

  @Test
  void testblacklisted05()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      co.id.btpn.web.monitoring.model.policy.anchore.Image image0 = new co.id.btpn.web.monitoring.model.policy.anchore.Image();
      blacklistedImage0.setImage(image0);
      co.id.btpn.web.monitoring.model.policy.anchore.Image image1 = blacklistedImage0.getImage();
      assertNull(image1.getValue());
  }

  @Test
  void testblacklisted06()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setId("");
      String string0 = blacklistedImage0.getId();
      assertEquals("", string0);
  }

  @Test
  void testblacklisted07()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      co.id.btpn.web.monitoring.model.policy.anchore.Image image0 = blacklistedImage0.getImage();
      assertNull(image0);
  }

  @Test
  void testblacklisted08()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      String string0 = blacklistedImage0.getId();
      assertNull(string0);
  }

  @Test
  void testblacklisted09()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      String string0 = blacklistedImage0.getRepository();
      assertNull(string0);
  }

  @Test
  void testblacklisted10()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setRegistry("");
      String string0 = blacklistedImage0.getRegistry();
      assertEquals("", string0);
  }

  @Test
  void testblacklisted11()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      blacklistedImage0.setId("/.dC5$|");
      String string0 = blacklistedImage0.getId();
      assertEquals("/.dC5$|", string0);
  }

  @Test
  void testblacklisted12()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      String string0 = blacklistedImage0.getName();
      assertNull(string0);
  }

  @Test
  void testblacklisted13()  throws Throwable  {
      BlacklistedImage blacklistedImage0 = new BlacklistedImage();
      String string0 = blacklistedImage0.getRegistry();
      assertNull(string0);
  }

  //param

  @Test
  void testparam0()  throws Throwable  {
      Param param0 = new Param();
      param0.setValue("8%UB5/");
      String string0 = param0.getValue();
      assertEquals("8%UB5/", string0);
  }

  @Test
  void testparam1()  throws Throwable  {
      Param param0 = new Param();
      param0.value = "";
      String string0 = param0.getValue();
      assertEquals("", string0);
  }

  @Test
  void testparam2()  throws Throwable  {
      Param param0 = new Param();
      param0.setName("");
      String string0 = param0.getName();
      assertEquals("", string0);
  }

  @Test
  void testparam3()  throws Throwable  {
      Param param0 = new Param();
      param0.desc = "$0g= gi7`Ig+p{^";
      String string0 = param0.getDesc();
      assertEquals("$0g= gi7`Ig+p{^", string0);
  }

  @Test
  void testparam4()  throws Throwable  {
      Param param0 = new Param();
      String string0 = param0.getDesc();
      assertNull(string0);
  }

  @Test
  void testparam5()  throws Throwable  {
      Param param0 = new Param();
      String string0 = param0.getName();
      assertNull(string0);
  }

  @Test
  void testparam6()  throws Throwable  {
      Param param0 = new Param();
      param0.setDesc("");
      String string0 = param0.getDesc();
      assertEquals("", string0);
  }

  @Test
  void testparam7()  throws Throwable  {
      Param param0 = new Param();
      String string0 = param0.getValue();
      assertNull(string0);
  }

  @Test
  void testparam8()  throws Throwable  {
      Param param0 = new Param();
      param0.setName("WR}|jHl{izbl");
      String string0 = param0.getName();
      assertEquals("WR}|jHl{izbl", string0);
  }

  //POLICY
  @Test
  void testpolicyanchore00()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.setId("t");
      assertNull(policy0.getVersion());
  }

  @Test
  void testpolicyanchore01()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.setVersion("S\"*53?|Ta9k[w9:3|hV");
      String string0 = policy0.getVersion();
      assertEquals("S\"*53?|Ta9k[w9:3|hV", string0);
  }

  @Test
  void testpolicyanchore02()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.setVersion("");
      String string0 = policy0.getVersion();
      assertEquals("", string0);
  }

  @Test
  void testpolicyanchore03()  throws Throwable  {
      Policy policy0 = new Policy();
      LinkedList<Rule> linkedList0 = new LinkedList<Rule>();
      policy0.setRules(linkedList0);
      List<Rule> list0 = policy0.getRules();
      assertTrue(list0.isEmpty());
  }

  @Test
  void testpolicyanchore04()  throws Throwable  {
      Policy policy0 = new Policy();
      LinkedList<Rule> linkedList0 = new LinkedList<Rule>();
      linkedList0.add((Rule) null);
      policy0.setRules(linkedList0);
      List<Rule> list0 = policy0.getRules();
      assertEquals(1, list0.size());
  }

  @Test
  void testpolicyanchore05()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.setName("HyQ+D%~q_y17B \"");
      String string0 = policy0.getName();
      assertEquals("HyQ+D%~q_y17B \"", string0);
  }

  @Test
  void testpolicyanchore06()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.name = "";
      String string0 = policy0.getName();
      assertEquals("", string0);
  }

  @Test
  void testpolicyanchore07()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.id = "t";
      String string0 = policy0.getId();
      assertEquals("t", string0);
  }

  @Test
  void testpolicyanchore08()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.id = "";
      String string0 = policy0.getId();
      assertEquals("", string0);
  }

  @Test
  void testpolicyanchore09()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.comment = "+y";
      String string0 = policy0.getComment();
      assertEquals("+y", string0);
  }

  @Test
  void testpolicyanchore10()  throws Throwable  {
      Policy policy0 = new Policy();
      policy0.setComment("");
      String string0 = policy0.getComment();
      assertEquals("", string0);
  }

  @Test
  void testpolicyanchore11()  throws Throwable  {
      Policy policy0 = new Policy();
      String string0 = policy0.getName();
      assertNull(string0);
  }

  @Test
  void testpolicyanchore12()  throws Throwable  {
      Policy policy0 = new Policy();
      String string0 = policy0.getId();
      assertNull(string0);
  }

  @Test
  void testpolicyanchore13()  throws Throwable  {
      Policy policy0 = new Policy();
      String string0 = policy0.getComment();
      assertNull(string0);
  }

  @Test
  void testpolicyanchore14()  throws Throwable  {
      Policy policy0 = new Policy();
      List<Rule> list0 = policy0.getRules();
      assertNull(list0);
  }

  @Test
  void testpolicyanchore15()  throws Throwable  {
      Policy policy0 = new Policy();
      String string0 = policy0.getVersion();
      assertNull(string0);
  }

 // rule anchore


 @Test
 void testruleanchorerule00()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.trigger = "ejSc\"1{sqWYm^hM`";
	 String string0 = rule0.getTrigger();
	 assertEquals("ejSc\"1{sqWYm^hM`", string0);
 }

 @Test
 void testruleanchorerule01()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.setTrigger("");
	 String string0 = rule0.getTrigger();
	 assertEquals("", string0);
 }

 @Test
 void testruleanchorerule02()  throws Throwable  {
	 Rule rule0 = new Rule();
	 LinkedList<Param> linkedList0 = new LinkedList<Param>();
	 rule0.params = (List<Param>) linkedList0;
	 List<Param> list0 = rule0.getParams();
	 assertTrue(list0.isEmpty());
 }

 @Test
 void testruleanchorerule03()  throws Throwable  {
	 Rule rule0 = new Rule();
	 LinkedList<Param> linkedList0 = new LinkedList<Param>();
	 Param param0 = new Param();
	 linkedList0.add(param0);
	 rule0.setParams(linkedList0);
	 List<Param> list0 = rule0.getParams();
	 assertFalse(list0.isEmpty());
 }

 @Test
 void testruleanchorerule04()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.id = "7gO*Q:~hn*8";
	 String string0 = rule0.getId();
	 assertEquals("7gO*Q:~hn*8", string0);
 }

 @Test
 void testruleanchorerule05()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.setId("");
	 String string0 = rule0.getId();
	 assertEquals("", string0);
 }

 @Test
 void testruleanchorerule06()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.setGate("EJ,@`");
	 String string0 = rule0.getGate();
	 assertEquals("EJ,@`", string0);
 }

 @Test
 void testruleanchorerule07()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.setGate("");
	 String string0 = rule0.getGate();
	 assertEquals("", string0);
 }

 @Test
 void testruleanchorerule08()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.setAction("Q1R9t=MHyOsL8");
	 String string0 = rule0.getAction();
	 assertEquals("Q1R9t=MHyOsL8", string0);
 }

 @Test
 void testruleanchorerule09()  throws Throwable  {
	 Rule rule0 = new Rule();
	 rule0.action = "";
	 String string0 = rule0.getAction();
	 assertEquals("", string0);
 }

 @Test
 void testruleanchorerule10()  throws Throwable  {
	 Rule rule0 = new Rule();
	 String string0 = rule0.getAction();
	 assertNull(string0);
 }

 @Test
 void testruleanchorerule11()  throws Throwable  {
	 Rule rule0 = new Rule();
	 String string0 = rule0.getId();
	 assertNull(string0);
 }

 @Test
 void testruleanchorerule12()  throws Throwable  {
	 Rule rule0 = new Rule();
	 List<Param> list0 = rule0.getParams();
	 assertNull(list0);
 }

 @Test
 void testruleanchorerule13()  throws Throwable  {
	 Rule rule0 = new Rule();
	 String string0 = rule0.getGate();
	 assertNull(string0);
 }

 @Test
 void testruleanchorerule14()  throws Throwable  {
	 Rule rule0 = new Rule();
	 String string0 = rule0.getTrigger();
	 assertNull(string0);
 }

 // item anchore 


 @Test
 void testitemanchore0()  throws Throwable  {
	 Item item0 = new Item();
	 item0.setTriggerId("t0J6,`;#$`i");
	 String string0 = item0.getTriggerId();
	 assertEquals("t0J6,`;#$`i", string0);
 }

 @Test
 void testitemanchore1()  throws Throwable  {
	 Item item0 = new Item();
	 item0.triggerId = "RA-%y8Zl7";
	 item0.triggerId = "";
	 String string0 = item0.getTriggerId();
	 assertEquals("", string0);
 }

 @Test
 void testitemanchore2()  throws Throwable  {
	 Item item0 = new Item();
	 item0.setId("t0J6,`;#$`i");
	 String string0 = item0.getId();
	 assertEquals("t0J6,`;#$`i", string0);
 }

 @Test
 void testitemanchore3()  throws Throwable  {
	 Item item0 = new Item();
	 item0.id = "";
	 String string0 = item0.getId();
	 assertEquals("", string0);
 }

 @Test
 void testitemanchore4()  throws Throwable  {
	 Item item0 = new Item();
	 item0.gate = "t0J6,`;#$`i";
	 String string0 = item0.getGate();
	 assertEquals("t0J6,`;#$`i", string0);
 }

 @Test
 void testitemanchore5()  throws Throwable  {
	 Item item0 = new Item();
	 item0.setGate("");
	 String string0 = item0.getGate();
	 assertEquals("", string0);
 }

 @Test
 void testitemanchore6()  throws Throwable  {
	 Item item0 = new Item();
	 String string0 = item0.getId();
	 assertNull(string0);
 }

 @Test
 void testitemanchore7()  throws Throwable  {
	 Item item0 = new Item();
	 String string0 = item0.getGate();
	 assertNull(string0);
 }

 @Test
 void testitemanchore8()  throws Throwable  {
	 Item item0 = new Item();
	 String string0 = item0.getTriggerId();
	 assertNull(string0);
 }

}
