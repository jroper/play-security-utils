package play.security.utils;

import play.mvc.With;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enforce a session timeout
 */
@With(SessionTimeoutAction.class)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface SessionTimeout {
    public SessionTimeoutMode mode() default SessionTimeoutMode.DEFAULT;
    public int sessionTimeout() default -1;
    public int lastAccessedUpdateInterval() default -1;
}
