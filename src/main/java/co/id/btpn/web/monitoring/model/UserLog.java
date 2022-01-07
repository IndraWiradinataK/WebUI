package co.id.btpn.web.monitoring.model;


import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.hibernate.annotations.GenericGenerator;

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
@Entity
public class UserLog {

    
    @Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "idgen")
	@GenericGenerator(name = "idgen", strategy="increment")
	@Column(name = "userlog_id")
	private Long id;
	@Column(name = "name")
	private String name;
	@Column(name = "activity")
	private String activity;
	@Column(name="logdate")
	private Date logDate;
	@Column(name="cn")
	private String cn;

	public  ZonedDateTime getInstanceLogDate(){
        
        if(this.logDate != null){
            return this.logDate.toInstant().atZone(ZoneId.of("Asia/Jakarta"));
        }else{
            return null;
        }
    }
}
