package com.example.auth_client_starter.properties;

import java.util.ArrayList;
import java.util.List;

public class UrlPermissionProperties {
    private  Boolean enable = false;

    private List<String> includeClientIds = new ArrayList<>();

    private List<String> exclusiveClientIds = new ArrayList<>();

    private String[] ignoreUrls = {};

    public Boolean getEnable() {
        return enable;
    }

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public List<String> getIncludeClientIds() {
        return includeClientIds;
    }

    public void setIncludeClientIds(List<String> includeClientIds) {
        this.includeClientIds = includeClientIds;
    }

    public List<String> getExclusiveClientIds() {
        return exclusiveClientIds;
    }

    public void setExclusiveClientIds(List<String> exclusiveClientIds) {
        this.exclusiveClientIds = exclusiveClientIds;
    }

    public String[] getIgnoreUrls() {
        return ignoreUrls;
    }

    public void setIgnoreUrls(String[] ignoreUrls) {
        this.ignoreUrls = ignoreUrls;
    }

    
}
