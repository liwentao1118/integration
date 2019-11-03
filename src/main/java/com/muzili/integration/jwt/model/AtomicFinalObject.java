package com.muzili.integration.jwt.model;

public class AtomicFinalObject <T> {

    private boolean isInitiated = false;

    private T value;

    public T getValue(){
        return value;
    }

    public synchronized boolean setValue(T value){

        if (isInitiated){
            return false;
        }
        this.isInitiated = true;
        this.value = value;
        return true;
    }

}
