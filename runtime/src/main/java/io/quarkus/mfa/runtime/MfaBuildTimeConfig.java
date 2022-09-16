package io.quarkus.mfa.runtime;

import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

@ConfigRoot(name = "mfa")
public class MfaBuildTimeConfig {

    /**
     * If the MFA extension is enabled.
     */
    @ConfigItem(defaultValue = "true")
    public boolean enabled;

    /**
     * The login view handler
     */
    @ConfigItem(defaultValue = "/mfa_login")
    public String loginView;

    /**
     * The logout view handler
     */
    @ConfigItem(defaultValue = "/mfa_logout")
    public String logoutView;

    /**
     * The login action handler
     */
    @ConfigItem(defaultValue = "/mfa_action")
    public String loginAction;

}
