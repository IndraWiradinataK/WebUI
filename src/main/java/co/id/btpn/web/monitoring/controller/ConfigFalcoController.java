package co.id.btpn.web.monitoring.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;

import co.id.btpn.web.monitoring.model.policy.anchore.Param;
import co.id.btpn.web.monitoring.service.OpenshiftClientService;
import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ConfigMapList;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.repository.UserLogRepository;
import co.id.btpn.web.monitoring.util.Util;


/**
 *
 * @author Ferry Fadly
 */
@Controller
@SessionAttributes("attributes")
public class ConfigFalcoController {


    @Autowired
    OpenshiftClientService openshiftClientService;

    @Value("${falco.config.namespace}")
    private String fNameSpace;

    @Value("${kubernetes.namespace}")
    private String kNameSpace;

	@Autowired
	private UserLogRepository userLogRepository;

	@Autowired
	private Util util;

	String PRETY_PREFIX = "<pre class='language-yaml'><code>";
	String PRETY_SUFIX = "</code></pre>";
    String PRETY_PREFIX_ = "<pre class=\"language-yaml\"><code>";
	

    @GetMapping("configfalcoindex")
    public String index( Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
      
    	// List <ConfigFalco> list= configFalcoService.findAll();
    	// model.addAttribute("list", list);
        

       ConfigMap cm =  openshiftClientService.getConnection().configMaps().inNamespace(fNameSpace).withName("falco").get();
       Map<String,String> map = cm.getData();
    

       List <Param> listObj =  new ArrayList <>();

        for (Map.Entry<String, String> entry : map.entrySet()){
            Param temp = new Param();
            temp.setName(entry.getKey());
            temp.setValue(entry.getValue());
            listObj.add(temp);
        }

        model.addAttribute("list", listObj);

    	return "auth/configfalco/index";
    }
    
    
    @GetMapping("configfalcoedit")
    public String edit(Param  paramFalco, Model model, @ModelAttribute("attributes") Map<?,?> attributes , @RequestParam String id) {
    	
    	// configFalco = configFalcoService.findById(id);
    	
    	// model.addAttribute("configFalco", configFalco);


       ConfigMap cm =  openshiftClientService.getConnection().configMaps().inNamespace(fNameSpace).withName("falco").get();
       Map<String,String> map = cm.getData();

       paramFalco.setName(id);
       paramFalco.setValue(PRETY_PREFIX+map.get(id)+PRETY_SUFIX);
        

        model.addAttribute("configFalco", paramFalco);
        
      
    	return "auth/configfalco/edit";
    }


    @PostMapping("configfalcoedit")
    public String editPost(Param  paramFalco, Model model, @ModelAttribute("attributes") Map<?,?> attributes) throws InvalidNameException {
        

       NonNamespaceOperation<ConfigMap, ConfigMapList, Resource<ConfigMap>>  cm =  openshiftClientService.getConnection().configMaps().inNamespace(fNameSpace);
       Map<String,String> map = cm.withName("falco").get().getData();

       System.out.println("after replace "+paramFalco.getValue().replace(PRETY_PREFIX, "").replace(PRETY_SUFIX, "").replace(PRETY_PREFIX_, ""));

    
       map.put(paramFalco.getName(), paramFalco.getValue().replace(PRETY_PREFIX, "").replace(PRETY_SUFIX, "").replace(PRETY_PREFIX_, ""));
   
       ConfigMap newConfigMap = new ConfigMapBuilder().withNewMetadata()
       .withName("falco")
       .withNamespace(fNameSpace)
       .addToLabels("app", "falco")
       .endMetadata()
       .addToData(map)
       .build();

       
       cm.createOrReplace(newConfigMap);

       UserLog userLog = new UserLog();
       userLog.setActivity("Update Config Falco File Name = \""+ paramFalco.getName() +"\"  ");
       userLog.setLogDate(new java.util.Date());
       userLog.setName(util.getLoggedUserName());
       userLog.setCn(util.getLoggedCN());
       userLogRepository.save(userLog);
       
       return "redirect:configfalcoindex";
    }
    
        
    @ModelAttribute("attributes")
    public Map<?,?> attributes() {
        return new HashMap<String,String>();
    }

}
