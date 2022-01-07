package co.id.btpn.web.monitoring.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.service.UserLogService;



/**
 *
 * @author Ferry Fadly
 */
@Controller
public class UserLogController {

	@Autowired
	UserLogService userLogService;
	
	

    @GetMapping("userlogindex")
    public String index(co.id.btpn.web.monitoring.dto.UserLog  userlog, Model model) {
      
    	List <UserLog> list= userLogService.findAll();
    	model.addAttribute("list", list);
        
    	return "auth/userlog/index";
    }

}
