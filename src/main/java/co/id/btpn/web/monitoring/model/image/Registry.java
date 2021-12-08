package co.id.btpn.web.monitoring.model.image;

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
public class Registry {


@SerializedName("created_at")
@Expose
public String createdAt;
@SerializedName("last_upated")
@Expose
public String lastUpated;
@SerializedName("registry_user")
@Expose
public String registryUser;
@SerializedName("registry_type")
@Expose
public String registryType;
@SerializedName("userId")
@Expose
public String userId;
@SerializedName("registry")
@Expose
public String registry;
@SerializedName("registry_name")
@Expose
public String registryName;
@SerializedName("registry_verify")
@Expose
public Boolean registryVerify;
@SerializedName("registry_pass")
@Expose
public String registryPass;

public  ZonedDateTime getInstanceCreatedAtDate(){
        
    if(this.createdAt != null){
        return Instant.parse(this.createdAt).atZone(ZoneId.of("Asia/Jakarta"));
    }else{
        return null;
    }
}

public  ZonedDateTime getInstanceLastUpatedDate(){
        
    if(this.lastUpated != null){
        return Instant.parse(this.lastUpated).atZone(ZoneId.of("Asia/Jakarta"));
    }else{
        return null;
    }
}

}