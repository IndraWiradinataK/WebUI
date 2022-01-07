package co.id.btpn.web.monitoring.model.image;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class Image {

    @SerializedName("analysis_status")
    @Expose
    public String analysisStatus;
    @SerializedName("analyzed_at")
    @Expose
    public String analyzedAt;
    @SerializedName("annotations")
    @Expose
    public Annotations annotations;
    @SerializedName("created_at")
    @Expose
    public String createdAt;
    @SerializedName("imageDigest")
    @Expose
    public String imageDigest;
    @SerializedName("image_content")
    @Expose
    public ImageContent imageContent;
    @SerializedName("image_detail")
    @Expose
    public List<ImageDetail> imageDetail = null;
    @SerializedName("image_status")
    @Expose
    public String imageStatus;
    @SerializedName("image_type")
    @Expose
    public String imageType;
    @SerializedName("last_updated")
    @Expose
    public String lastUpdated;
    @SerializedName("parentDigest")
    @Expose
    public String parentDigest;
    @SerializedName("userId")
    @Expose
    public String userId;
    

    public  ZonedDateTime getInstanceAnalyzedAtDate(){
        
        if(this.analyzedAt != null){
            return Instant.parse(this.analyzedAt).atZone(ZoneId.of("Asia/Jakarta"));
        }else{
            return Instant.parse(this.createdAt).atZone(ZoneId.of("Asia/Jakarta"));
        }
    }

}
