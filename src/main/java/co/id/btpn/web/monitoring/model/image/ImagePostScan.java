package co.id.btpn.web.monitoring.model.image;

import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class ImagePostScan {

   
    @SerializedName("annotations")
    @Expose
    public Annotations annotations;
    @SerializedName("tag")
    @Expose
    public String tag;

}
