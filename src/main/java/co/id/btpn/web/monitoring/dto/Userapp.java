package co.id.btpn.web.monitoring.dto;

import java.util.Date;

import co.id.btpn.web.monitoring.model.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 *
 * @author Ferry Fadly
 */
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Userapp extends co.id.btpn.web.monitoring.model.Userapp {

	
	private Long id;
	private String name;
	private int active;
	private String cn;

	
	private String createdBy;
	private java.util.Date createdDate;
	private String modifiedBy;
	private Date modifiedDate;

	private Role roleId;
}
