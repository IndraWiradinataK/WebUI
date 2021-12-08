package co.id.btpn.web.monitoring.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.JsonIOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.SessionAttributes;

import co.id.btpn.web.monitoring.model.PodExt;
import co.id.btpn.web.monitoring.service.OpenshiftClientService;
import io.fabric8.kubernetes.api.model.Pod;

/**
 *
 * @author Ferry Fadly
 */
@Controller
@SessionAttributes("attributes")
public class RootController {

    @Value("${kibana.dashboard.url}")
    private String kibanaUrl;

    @Autowired
    OpenshiftClientService openshiftClientService;

    @GetMapping("/")
    public String root() {
        return "login";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/access-denied")
    public String denied() {
        return "access-denied";
    }

    

    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, Model model, @ModelAttribute("attributes") Map<?, ?> attributes) {

        
        model.addAttribute("kibanaUrl", kibanaUrl);
        return "auth/dashboard";
    }

    @GetMapping("servicestatusindex")
    public String serviceStatus(Model model, @ModelAttribute("attributes") Map<?, ?> attributes)
            throws JsonIOException, IOException {

        List<PodExt> pods = new ArrayList<>();

        for (Pod iterable_element : openshiftClientService.getConnection().pods().list().getItems()) {
            PodExt podExt = new PodExt(iterable_element);
            pods.add(podExt);
        }

        model.addAttribute("list", pods);
        return "auth/servicestatus/index";
    }

    @ModelAttribute("attributes")
    public Map<String, String> attributes() {
        return new HashMap<String, String>();
    }

}
