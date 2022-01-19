package co.id.btpn.web.monitoring.controller;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import co.id.btpn.web.monitoring.model.Role;
import co.id.btpn.web.monitoring.model.Userapp;
import co.id.btpn.web.monitoring.service.RoleService;
import co.id.btpn.web.monitoring.service.UserappService;
import co.id.btpn.web.monitoring.util.Util;
import co.id.btpn.web.monitoring.service.LdapSearchService;


/**
 *
 * @author Ferry Fadly
 */
@Controller
public class UserappController {

	@Autowired
	UserappService userappService;

    @Autowired
	RoleService roleService;


    @Autowired
    LdapSearchService ldapSearchService;
	
    @Autowired
	private Util util;
	
    @GetMapping("userappindex")
    public String index(co.id.btpn.web.monitoring.dto.Userapp  userapp, Model model) {
      
    	List <Userapp> list= userappService.findAll();
        
    	model.addAttribute("list", list);
        
    	return "auth/userapp/index";
    }
    
    @GetMapping("userappadd")
    public String add(co.id.btpn.web.monitoring.dto.Userapp  userapp, Model model) {
        
    	List <Role> list= roleService.findAll();

    	model.addAttribute("roleList", list);
        
    	
    	return "auth/userapp/add";
    }


    @PostMapping("userappadd")
    public String addPost(Userapp  userapp, Model model) { //NOSONAR
        
    	userappService.save( userapp);
    	
    	return "redirect:userappindex";
    }
    
    
    @GetMapping("userappedit")
    public String edit(co.id.btpn.web.monitoring.dto.Userapp  userapp, Model model, @RequestParam Long id) {
        

    	List <Role> list= roleService.findAll();


    	model.addAttribute("roleList", list);
    	
    	Userapp userappDB = userappService.findById(id);
    	model.addAttribute("userapp", userappDB);
        
    	
    	return "auth/userapp/edit";
    }


    @PostMapping("userappedit")
    public String editPost(Userapp  userapp, Model model) {//NOSONAR
        
    
    	userappService.update(userapp);
    	
    	return "redirect:userappindex";
    }
    
    
    @GetMapping("userappdelete")
    public String delete(co.id.btpn.web.monitoring.dto.Userapp  userapp, Model model, @RequestParam Long id) {
          	
    	userappService.deactiveById(id);
    	
    	return "redirect:userappindex";
    }

    @PostMapping("uservalidation")
    public  @ResponseBody List<Map<String, Object>> userValidation( @RequestParam Map<String,String> allParams ) throws IOException {

    	String name = "";

        if(!util.isUserLoggedIn()){
            return  Collections.emptyList() ;
        }
        
    	if (allParams.containsKey("name")){
    		name =  allParams.get("name");
    	}

        List<Map<String, Object>> lp = ldapSearchService.getPersonNamesByAccountName(name);

    	return lp;
    }
    
}
