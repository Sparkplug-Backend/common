package com.sparkplug.common.exception;

public class ResourceNotFoundException extends ApplicationException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String resourceName, Long id) {
        super(resourceName + " with id '" + id + "' not found.");
    }

    @Override
    public int getStatusCode() {
        return 404;
    }
}
