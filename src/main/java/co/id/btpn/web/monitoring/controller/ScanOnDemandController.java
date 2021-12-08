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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.model.image.Annotations;
import co.id.btpn.web.monitoring.model.image.Image;
import co.id.btpn.web.monitoring.model.image.ImagePostScan;
import co.id.btpn.web.monitoring.repository.UserLogRepository;
import co.id.btpn.web.monitoring.util.Util;
import net.bytebuddy.asm.Advice.Return;



/**
 *
 * @author Ferry Fadly
 */
@Controller
@SessionAttributes("attributes")
public class ScanOnDemandController {


    
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


    
    @GetMapping("scanondemandindex") public String scanOnDemand(Model model, @ModelAttribute("attributes") Map<?,?> attributes) { 
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        Map<String, String> bodyParamMap = new HashMap<String, String>();

        HttpEntity requestEntity = new HttpEntity(bodyParamMap,headers);
        
        ResponseEntity<String> responseEntity =  restTemplate.exchange(anchoreUrl+"/images", HttpMethod.GET, requestEntity, String.class);
    
        Image[] imageList = new Gson().fromJson(responseEntity.getBody().toString(), Image[].class);

        model.addAttribute("list", imageList);

        return "auth/scanondemand/index"; 
    }

    @PostMapping("scanondemandadd")
    public  @ResponseBody String updateCustomRule( @RequestBody Map<String, String> allParams ) throws IOException, InvalidNameException  {

    	String tag = "";

        if(!util.isUserLoggedIn()){
            return "SESSION_EXPIRED";
        }

    	Annotations annotations = new Annotations();
        annotations.setOrigins("webui");

        if (allParams.containsKey("tag")){
    		tag =  allParams.get("tag");
    	}

        ImagePostScan post = new ImagePostScan();
        post.setTag(tag);
        post.setAnnotations(annotations);


     
        UserLog userLog = new UserLog();
        userLog.setActivity("Add New Scan Request = \""+ tag +"\"  ");
        userLog.setLogDate(new java.util.Date());
        userLog.setName(util.getLoggedUserName());
        userLog.setCn(util.getLoggedCN());
        userLogRepository.save(userLog);

        HttpHeaders headers = new HttpHeaders();
        
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBasicAuth(anchoreUsername, anchorePassword);

        HttpEntity requestEntity = new HttpEntity(post,headers);

      

        ResponseEntity<String> responseEntity = null;
        
        try {
            responseEntity = restTemplate.exchange(anchoreUrl+"/images", HttpMethod.POST, requestEntity, String.class);
        }catch(HttpClientErrorException e) {
            return new ResponseEntity<>(e.getResponseBodyAsString(), HttpStatus.BAD_REQUEST).getBody();
        }catch(HttpServerErrorException e) {
            return new ResponseEntity<>(e.getResponseBodyAsString(), HttpStatus.INTERNAL_SERVER_ERROR).getBody();
        }catch(Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR).getBody();
        }

    	return new ResponseEntity<>(responseEntity.getBody(), HttpStatus.OK).getBody();
    }

    
    
    
        
    @ModelAttribute("attributes")
    public Map<?,?> attributes() {
        return new HashMap<String,String>();
    }

}
