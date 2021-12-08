
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
public class Mapping {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("name")
    @Expose
    public String name;
    @SerializedName("whitelist_ids")
    @Expose
    public List<String> whitelistIds = null;
    @SerializedName("policy_id")
    @Expose
    public String policyId;
    @SerializedName("policy_ids")
    @Expose
    public List<String> policyIds = null;
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
