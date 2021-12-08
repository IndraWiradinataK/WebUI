

package co.id.btpn.web.monitoring.model.policy.anchore;


import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import javax.annotation.Generated;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Generated("jsonschema2pojo")
public class Policies {



   
    @SerializedName("description")
    @Expose
    public String description;
    @SerializedName("name")
    @Expose
    public String name;

    @SerializedName("created_at")
    @Expose
    public String createdAt;
    @SerializedName("last_updated")
    @Expose
    public String lastUpdated;
    @SerializedName("policyId")
    @Expose
    public String policyId;
    @SerializedName("active")
    @Expose
    public Boolean active;
    @SerializedName("userId")
    @Expose
    public String userId;
    @SerializedName("policy_source")
    @Expose
    public String policySource;
    @SerializedName("policybundle")
    @Expose
    public Policybundle policybundle;

    public  ZonedDateTime getInstanceLastUpdatedDate(){
        
        if(this.lastUpdated != null){
            return Instant.parse(this.lastUpdated).atZone(ZoneId.of("Asia/Jakarta"));
        }else{
            return null;
        }
    }

    public  ZonedDateTime getInstanceCreatedAtDate(){
        
        if(this.createdAt != null){
            return Instant.parse(this.createdAt).atZone(ZoneId.of("Asia/Jakarta"));
        }else{
            return null;
        }
    }

}
