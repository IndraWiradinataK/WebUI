
package co.id.btpn.web.monitoring.model.image;

import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

@Generated("jsonschema2pojo")
public class Metadata {

    @SerializedName("arch")
    @Expose
    public String arch;
    @SerializedName("distro")
    @Expose
    public String distro;
    @SerializedName("distro_version")
    @Expose
    public String distroVersion;
    @SerializedName("dockerfile_mode")
    @Expose
    public String dockerfileMode;
    @SerializedName("image_size")
    @Expose
    public Integer imageSize;
    @SerializedName("layer_count")
    @Expose
    public Integer layerCount;

}
