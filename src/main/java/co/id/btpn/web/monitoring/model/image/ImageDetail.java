package co.id.btpn.web.monitoring.model.image;

import javax.annotation.Generated;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

@Generated("jsonschema2pojo")
public class ImageDetail {

    @SerializedName("created_at")
    @Expose
    public String createdAt;
    @SerializedName("digest")
    @Expose
    public String digest;
    @SerializedName("dockerfile")
    @Expose
    public String dockerfile;
    @SerializedName("fulldigest")
    @Expose
    public String fulldigest;
    @SerializedName("fulltag")
    @Expose
    public String fulltag;
    @SerializedName("imageDigest")
    @Expose
    public String imageDigest;
    @SerializedName("imageId")
    @Expose
    public String imageId;
    @SerializedName("last_updated")
    @Expose
    public String lastUpdated;
    @SerializedName("registry")
    @Expose
    public String registry;
    @SerializedName("repo")
    @Expose
    public String repo;
    @SerializedName("tag")
    @Expose
    public String tag;
    @SerializedName("tag_detected_at")
    @Expose
    public String tagDetectedAt;
    @SerializedName("userId")
    @Expose
    public String userId;

}
