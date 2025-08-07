package com.example.auth_client_starter.properties;

import java.util.ArrayList;
import java.util.List;

public class RenewProperties{
    private Boolean enable = false;

    private List<String> includeClientIds = new ArrayList();

    private List<String> exclusiveClientIds = new ArrayList();

    private Double timeRatio = 0.5;

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public void setIncludeClientIds(List<String> includeClientIds) {
        this.includeClientIds = includeClientIds;
    }

    public void setExclusiveClientIds(List<String> exclusiveClientIds) {
        this.exclusiveClientIds = exclusiveClientIds;
    }

    public void setTimeRatio(Double timeRatio) {
        this.timeRatio = timeRatio;
    }

    public Boolean getEnable() {
        return enable;
    }

    public List<String> getIncludeClientIds() {
        return includeClientIds;
    }

    public List<String> getExclusiveClientIds() {
        return exclusiveClientIds;
    }

    public Double getTimeRatio() {
        return timeRatio;
    }

    
}