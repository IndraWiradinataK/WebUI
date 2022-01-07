package co.id.btpn.web.monitoring.service;

import java.util.List;
import java.util.Map;

public interface LdapSearchService {
	List<Map<String, Object>> getPersonNamesByAccountName(String search);
}
