package co.id.btpn.web.monitoring.service;

import java.util.List;

import co.id.btpn.web.monitoring.model.Role;

public interface RoleService {

	void save(Role role);

	List<Role> findAll() ;

	Role findById(long pId);
	
	void update(Role role);

}
