

package co.id.btpn.web.monitoring.model.policy.anchore;


import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class BlacklistedImage {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("name")
    @Expose
    public String name;
    @SerializedName("registry")
    @Expose
    public String registry;
    @SerializedName("repository")
    @Expose
    public String repository;
    @SerializedName("image")
    @Expose
    public Image image;

}
