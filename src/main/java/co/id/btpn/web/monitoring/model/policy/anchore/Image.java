

package co.id.btpn.web.monitoring.model.policy.anchore;


import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class Image {

    @SerializedName("type")
    @Expose
    public String type;
    @SerializedName("value")
    @Expose
    public String value;

}
