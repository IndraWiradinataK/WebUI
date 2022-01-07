package co.id.btpn.web.monitoring.service.impl;

import java.util.Date;
import java.util.List;

import javax.naming.InvalidNameException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.model.Userapp;
import co.id.btpn.web.monitoring.repository.UserLogRepository;
import co.id.btpn.web.monitoring.repository.UserappRepository;
import co.id.btpn.web.monitoring.service.UserappService;
import co.id.btpn.web.monitoring.util.Util;



@Service("userappService")
public class UserappServiceImpl implements UserappService{

	@Autowired
	private UserappRepository userappRepository;

	@Autowired
	private UserLogRepository userLogRepository;

	@Autowired
	private Util util;

	private static final Logger LOG = LoggerFactory.getLogger(UserappServiceImpl.class);

	
	@Override
	public void save(Userapp user)  {
		
		List<Userapp>  userappList = userappRepository.findByName(user.getName());
      
		if(userappList.size()>0){
			//user = userappList.get(0);
			user.setId(userappList.get(0).getId()); 
		}

        user.setActive(1);
		user.setCreatedBy(util.getLoggedUserName());
		user.setCreatedDate(new Date());

		UserLog userLog = new UserLog();
		userLog.setActivity("Add User \""+user.getName() +"\" ");
		userLog.setLogDate(new Date());
		userLog.setName(util.getLoggedUserName());
		try {
			userLog.setCn(util.getLoggedCN());
		} catch (InvalidNameException e) {
			LOG.error(">>>>>save InvalidNameException ",e);
		}
		userLogRepository.save(userLog);
		
		userappRepository.save(user);
	}

	@Override
	public List<Userapp> findAll() {
		return  userappRepository.findAll();
	}

	@Override
	public Userapp findById(long pId) {
		return userappRepository.findById(pId).orElse(null);
	}
	
	@Override
	public void update(Userapp userapp) {

		//CHECK IF THE NAME IS SAME 
		List<Userapp>  userappList = userappRepository.findByName(userapp.getName());
      
		if(userappList.size()>0){
			
			userapp.setId(userappList.get(0).getId()); 
		}

		//updatePageSlugWithTitle(p1);
		userapp.setModifiedBy(util.getLoggedUserName());
		userapp.setModifiedDate(new Date());

		UserLog userLog = new UserLog();
		userLog.setActivity("Update User \""+userapp.getName() +"\" ");
		userLog.setLogDate(new Date());
		userLog.setName(util.getLoggedUserName());
		try {
			userLog.setCn(util.getLoggedCN());
		} catch (InvalidNameException e) {
			LOG.error(">>>>>update InvalidNameException ",e);
		}
		userLogRepository.save(userLog);

		userappRepository.save(userapp);
	}


	@Override
	public void deactiveById(long pId) {
		Userapp userapp = userappRepository.findById(pId).orElse(null);
		if(userapp != null){
			userapp.setActive(0);
			userapp.setModifiedBy(util.getLoggedUserName());
			userapp.setModifiedDate(new Date());

			UserLog userLog = new UserLog();
			userLog.setActivity("Deactivated User \""+userapp.getName() +"\" ");
			userLog.setLogDate(new Date());
			userLog.setName(util.getLoggedUserName());
			try {
				userLog.setCn(util.getLoggedCN());
			} catch (InvalidNameException e) {
				LOG.error(">>>>>deactiveById InvalidNameException ",e);
			}
			userLogRepository.save(userLog);

			userappRepository.save(userapp);
		}
	}

	@Override
	public List<Userapp> findByName(String name){
		return userappRepository.findByName(name);
	}

}
