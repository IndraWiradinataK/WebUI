package co.id.btpn.web.monitoring.model;


import lombok.Getter;
import lombok.Setter;
import io.fabric8.kubernetes.api.model.ContainerStatus;
import io.fabric8.kubernetes.api.model.Pod;

/**
 *
 * @author Ferry Fadly
 */
@Setter
@Getter
public class PodExt extends Pod{

	
    public PodExt(Pod pod) {
        super();
        this.setApiVersion(pod.getApiVersion());
        this.setKind(pod.getKind());
        this.setMetadata(pod.getMetadata());
        this.setSpec(pod.getSpec());
        this.setStatus(pod.getStatus());
    }

	public int getCountRestart(){
		int restartCount = 0;
		for (ContainerStatus iterable_element : getStatus().getContainerStatuses()) {
			restartCount= restartCount+iterable_element.getRestartCount();
		}
		return restartCount;
	}

	public int getCountContainerReady(){
		int readyCount = 0;
		for (ContainerStatus iterable_element : getStatus().getContainerStatuses()) {
			if(Boolean.TRUE.equals(iterable_element.getReady())){
				readyCount= readyCount+1;
			}
		}
		return readyCount;
	}

	public int getCountContainer(){	
		return getStatus().getContainerStatuses().size();
	}

	public String getContainerReadyStatus(){
		return getCountContainerReady()+"/"+getCountContainer();
	}
	
}
