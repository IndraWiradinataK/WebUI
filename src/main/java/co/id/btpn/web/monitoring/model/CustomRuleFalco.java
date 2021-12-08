package co.id.btpn.web.monitoring.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;


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
public class CustomRuleFalco {


	@SerializedName("action_name")
	@Expose
	public String actionName;
	@SerializedName("enabled")
	@Expose
	public Integer enabled;
	@SerializedName("id")
	@Expose
	public Integer id;
	@SerializedName("rule_name")
	@Expose
	public String ruleName;
	
}
