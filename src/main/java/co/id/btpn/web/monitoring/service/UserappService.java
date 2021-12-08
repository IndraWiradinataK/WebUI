package co.id.btpn.web.monitoring.service;

import java.util.List;

import co.id.btpn.web.monitoring.model.Userapp;

public interface UserappService {

	void save(Userapp userapp);

	List<Userapp> findAll() ;

	Userapp findById(long pId);
	
	void update(Userapp userapp);
	
	void deactive(Userapp userapp);

	void deactiveById(long id);

	List<Userapp> findByName(String name);

}
