package com.programming.techie.springngblog.exception;

public class SpringBlogException extends RuntimeException {
    public SpringBlogException(String exception_occured) {
        System.out.println(exception_occured);
    }
}
