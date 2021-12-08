package co.id.btpn.web.monitoring.controller;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;

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
@SessionAttributes("attributes")
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
    public String index(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?> attributes) {
      
    	List <Userapp> list= userappService.findAll();
        
    	model.addAttribute("list", list);
        
    	return "auth/userapp/index";
    }
    
    @GetMapping("userappadd")
    public String add(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?>  attributes) {
        
    	List <Role> list= roleService.findAll();
        System.out.println("Role Count >>>> "+list.size());

    	model.addAttribute("roleList", list);
        
    	
    	return "auth/userapp/add";
    }


    @PostMapping("userappadd")
    public String addPost(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?>  attributes) {
        
    	userappService.save(userapp);;
    	
    	return "redirect:userappindex";
    }
    
    
    @GetMapping("userappedit")
    public String edit(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?>  attributes , @RequestParam Long id) {
        

    	List <Role> list= roleService.findAll();

        System.out.println("Role Count >>>> "+list.size());

    	model.addAttribute("roleList", list);
    	
    	userapp = userappService.findById(id);
    	
    	model.addAttribute("userapp", userapp);
        
    	
    	return "auth/userapp/edit";
    }


    @PostMapping("userappedit")
    public String editPost(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?>  attributes) {
        
    	userappService.update(userapp);;
    	
    	return "redirect:userappindex";
    }
    
    
    @GetMapping("userappdelete")
    public String delete(Userapp  userapp, Model model, @ModelAttribute("attributes") Map<?,?>  attributes , @RequestParam Long id) {
          	
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
        
    @ModelAttribute("attributes")
    public Map<?,?>  attributes() {
        return new HashMap<String,String>();
    }

}
