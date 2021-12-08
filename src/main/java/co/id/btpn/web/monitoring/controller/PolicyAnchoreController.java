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
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
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
@SessionAttributes("attributes")
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
    public String index(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
      
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        Map<String, String> bodyParamMap = new HashMap<String, String>();

        HttpEntity requestEntity = new HttpEntity(bodyParamMap,headers);
        
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies", HttpMethod.GET, requestEntity, String.class);
    
        Policies[] policyList = new Gson().fromJson(responseEntity.getBody().toString(), Policies[].class);

        model.addAttribute("list", policyList);

        Gson gson = new Gson();
        String json = gson.toJson(policyList);

        
    	return "auth/policyanchore/index";
    }
    
    @GetMapping("policyanchoreadd")
    public String add(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
        
    	
    	return "auth/policyanchore/add";
    }


    @PostMapping("policyanchoreadd")
    public String addPost(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
        
    
        HttpHeaders headers = new HttpHeaders();
        
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);


        Gson gson = new Gson();
        String json = gson.toJson(policies);

        HttpEntity requestEntity = new HttpEntity(json,headers);
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies", HttpMethod.POST, requestEntity, String.class);
              
    	
    	return "redirect:policyanchoreindex";
    }
    
    
    @GetMapping("policyanchoreedit")
    public String edit(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes , @RequestParam String id) {
    	
    	HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        Map<String, String> bodyParamMap = new HashMap<String, String>();

        HttpEntity requestEntity = new HttpEntity(bodyParamMap,headers);
        
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+id, HttpMethod.GET, requestEntity, String.class);

        Policies[] imageList = new Gson().fromJson(responseEntity.getBody().toString(), Policies[].class);

        model.addAttribute("policies", imageList[0]); 



    	return "auth/policyanchore/edit";
    }


    @PostMapping("policyanchoreedit")
    public String editPost(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
        
    
        HttpHeaders headers = new HttpHeaders();
        
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);


        Gson gson = new Gson();
        String json = gson.toJson(policies);

        HttpEntity requestEntity = new HttpEntity(json,headers);
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+policies.getPolicyId(), HttpMethod.PUT, requestEntity, String.class);
              
    	
    	return "redirect:policyanchoreindex";
    }
    
    
    @GetMapping("policyanchoredelete")
    public String delete(Policies policies, Model model, @ModelAttribute("attributes") Map<?,?> attributes , @RequestParam String id) {
          	
        HttpHeaders headers = new HttpHeaders();
        
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        policies = new Policies();
        policies.setPolicyId(id);

        Gson gson = new Gson();
        String json = gson.toJson(policies);

        HttpEntity requestEntity = new HttpEntity(json,headers);
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+policies.getPolicyId(), HttpMethod.DELETE, requestEntity, String.class);
    	
    	return "redirect:policyanchoreindex";
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
        Map<String, String> bodyParamMap = new HashMap<String, String>();
        HttpEntity requestEntity = new HttpEntity(bodyParamMap,headers);

        //load data before update
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+id, HttpMethod.GET, requestEntity, String.class);
        Policies[] imageList = new Gson().fromJson(responseEntity.getBody().toString(), Policies[].class);


        Policies temp = imageList[0];
        temp.setActive(enabled);

        Gson gson = new Gson();
        String json = gson.toJson(temp);
        String jsonw = gson.toJson(imageList);

        //save/update data
        requestEntity = new HttpEntity(json,headers);
        responseEntity =  restTemplate.exchange(anchoreUrl+"/policies/"+id, HttpMethod.PUT, requestEntity, String.class);
    

        UserLog userLog = new UserLog();
        userLog.setActivity("Update Scanning Policy = \""+ temp.getName() +"\", enabled = \""+ (enabled ? "Enable" : "Disabled") +"\" , ID = "+id+" ");
        userLog.setLogDate(new java.util.Date());
        userLog.setName(util.getLoggedUserName());
        userLog.setCn(util.getLoggedCN());
        userLogRepository.save(userLog);
        


    	return responseEntity.getBody();
    }
        
    @ModelAttribute("attributes")
    public Map<?,?> attributes() {
        return new HashMap<String,String>();
    }

}
