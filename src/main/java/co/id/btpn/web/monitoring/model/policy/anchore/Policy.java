

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
public class Policy {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("name")
    @Expose
    public String name;
    @SerializedName("comment")
    @Expose
    public String comment;
    @SerializedName("version")
    @Expose
    public String version;
    @SerializedName("rules")
    @Expose
    public List<Rule> rules = null;

}
