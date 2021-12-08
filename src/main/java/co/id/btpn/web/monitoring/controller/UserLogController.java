package co.id.btpn.web.monitoring.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.SessionAttributes;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.service.UserLogService;



/**
 *
 * @author Ferry Fadly
 */
@Controller
@SessionAttributes("attributes")
public class UserLogController {

	@Autowired
	UserLogService userLogService;
	
	

    @GetMapping("userlogindex")
    public String index(UserLog  userlog, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
      
    	List <UserLog> list= userLogService.findAll();
    	model.addAttribute("list", list);
        
    	return "auth/userlog/index";
    }
    
    @ModelAttribute("attributes")
    public Map<?,?>  attributes() {
        return new HashMap<String,String>();
    }

}
