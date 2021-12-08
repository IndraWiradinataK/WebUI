package co.id.btpn.web.monitoring.service;

import io.fabric8.openshift.client.OpenShiftClient;

public interface OpenshiftClientService {
	OpenShiftClient getConnection();

}
