package co.id.btpn.web.monitoring.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import co.id.btpn.web.monitoring.model.UserLog;
import co.id.btpn.web.monitoring.repository.UserLogRepository;
import co.id.btpn.web.monitoring.service.UserLogService;



@Service("userLogService")
public class UserLogServiceImpl implements UserLogService{

	@Autowired
	private UserLogRepository userLogRepository;

	
	@Override
	public List<UserLog> findAll() {
		return  userLogRepository.findAll();
	}

	@Override
	public UserLog findById(long pId) {
		return userLogRepository.findById(pId).orElse(null);
	}
	

}
