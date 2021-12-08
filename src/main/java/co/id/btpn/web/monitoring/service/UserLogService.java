package co.id.btpn.web.monitoring.service;

import java.util.List;

import co.id.btpn.web.monitoring.model.UserLog;

public interface UserLogService {

	List<UserLog> findAll() ;

	UserLog findById(long pId);

}
