
package co.id.btpn.web.monitoring.model.policy.anchore;


import java.util.List;
import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

@Generated("jsonschema2pojo")
public class Whitelist {

    @SerializedName("id")
    @Expose
    public String id;
    @SerializedName("name")
    @Expose
    public String name;
    @SerializedName("version")
    @Expose
    public String version;
    @SerializedName("comment")
    @Expose
    public String comment;
    @SerializedName("items")
    @Expose
    public List<Item> items = null;

}
