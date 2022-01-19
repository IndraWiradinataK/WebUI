package co.id.btpn.web.monitoring.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.naming.InvalidNameException;

import com.google.gson.Gson;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import co.id.btpn.web.monitoring.model.policy.anchore.Policies;


import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.repository.UserLogRepository;
import co.id.btpn.web.monitoring.util.Util;


/**
 *
 * @author Ferry Fadly
 */
@Controller
public class PolicyAnchoreController {

	
    @Value("${anchore.url}")
    private String anchoreUrl;

    @Value("${anchore.username}")
    private String anchoreUsername;

    @Value("${anchore.password}")
    private String anchorePassword;

    @Autowired
    private RestTemplate restTemplate;
	

	@Autowired
	private UserLogRepository userLogRepository;

	@Autowired
	private Util util;

    @GetMapping("policyanchoreindex")
    public String index(Policies policies, Model model) {
      
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        Map<String, String> bodyParamMap = new HashMap<>();

        HttpEntity <?> requestEntity = new HttpEntity<>(bodyParamMap,headers);
        
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies", HttpMethod.GET, requestEntity, String.class);
    

        Object responseBody =responseEntity.getBody();
        Policies[] policyList = null;
        if(responseBody!=null){
            policyList= new Gson().fromJson(responseBody.toString(), Policies[].class);
        }


        model.addAttribute("list", policyList);
        
    	return "auth/policyanchore/index";
    }
    

    @PostMapping("policyanchoreupdate")
    public  @ResponseBody String updateActive( @RequestParam Map<String,String> allParams ) throws IOException, InvalidNameException  {

    	Boolean enabled = false;
    	String id = "";

        if (allParams.containsKey("id")){
    		id =  allParams.get("id");
    	}


    	if (allParams.containsKey("enabled")){
    		enabled =  Boolean.parseBoolean(allParams.get("enabled"));
    	}
        

        if(!util.isUserLoggedIn()){
            return "SESSION_EXPIRED";
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        headers.setBasicAuth(anchoreUsername, anchorePassword);
        Map<String, String> bodyParamMap = new HashMap<>();
        HttpEntity <?> requestEntity = new HttpEntity<>(bodyParamMap,headers);

        //load data before update
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+id, HttpMethod.GET, requestEntity, String.class);
        
        Object responseBody =responseEntity.getBody();
        Policies[] policyList ;
        Policies temp =  new Policies();
        if(responseBody!=null){
            policyList= new Gson().fromJson(responseBody.toString(), Policies[].class);
        

        temp = policyList[0];
        temp.setActive(enabled);

        Gson gson = new Gson();
        String json = gson.toJson(temp);

        //save/update data
        requestEntity = new HttpEntity<>(json,headers);
        responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+id, HttpMethod.PUT, requestEntity, String.class);
        }

        UserLog userLog = new UserLog();
        userLog.setActivity("Update Scanning Policy = \""+ temp.getName() +"\", enabled = \""+ (enabled ? "Enable" : "Disabled") +"\" , ID = "+id+" ");
        userLog.setLogDate(new java.util.Date());
        userLog.setName(util.getLoggedUserName());
        userLog.setCn(util.getLoggedCN());
        userLogRepository.save(userLog);

    	return responseEntity.getBody();
    }
        
}
