

package co.id.btpn.web.monitoring.model.policy.anchore;


import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class Item {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("gate")
    @Expose
    public String gate;
    @SerializedName("trigger_id")
    @Expose
    public String triggerId;

}
