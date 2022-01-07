package co.id.btpn.web.monitoring.dto;


import java.util.Date;


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
public class UserLog extends co.id.btpn.web.monitoring.model.UserLog {

    
    private Long id;
	private String name;
	private String activity;
	private Date logDate;
	private String cn;

}
