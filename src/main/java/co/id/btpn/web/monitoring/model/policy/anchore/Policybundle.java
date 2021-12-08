
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
public class Policybundle {

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
    @SerializedName("whitelists")
    @Expose
    public List<Whitelist> whitelists = null;
    @SerializedName("policies")
    @Expose
    public List<Policy> policies = null;
    @SerializedName("mappings")
    @Expose
    public List<Mapping> mappings = null;
    @SerializedName("whitelisted_images")
    @Expose
    public List<WhitelistedImage> whitelistedImages = null;
    @SerializedName("blacklisted_images")
    @Expose
    public List<BlacklistedImage> blacklistedImages = null;

}
