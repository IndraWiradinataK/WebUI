

package co.id.btpn.web.monitoring.model.policy.anchore;


import java.util.List;
import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class Rule {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("gate")
    @Expose
    public String gate;
    @SerializedName("trigger")
    @Expose
    public String trigger;
    @SerializedName("action")
    @Expose
    public String action;
    @SerializedName("params")
    @Expose
    public List<Param> params = null;

}
