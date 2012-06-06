package play.security.utils;

import play.api.security.utils.SessionTimeoutMode$;

/**
 * The session timeout mode
 */
public enum SessionTimeoutMode {
    MAX_LENGTH(play.api.security.utils.SessionTimeoutMode.MaxLength()),
    LAST_ACCESSED(play.api.security.utils.SessionTimeoutMode.LastAccessed()),
    DEFAULT;

    private SessionTimeoutMode(SessionTimeoutMode$.Value scalaMode) {
        this.scalaMode = scalaMode;
    }

    private SessionTimeoutMode() {
        scalaMode = null;
    }

    public final SessionTimeoutMode$.Value scalaMode;
}
