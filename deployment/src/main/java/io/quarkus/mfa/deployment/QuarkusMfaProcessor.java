package io.quarkus.mfa.deployment;

import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.mfa.runtime.MfaAuthenticationMechanism;
import io.quarkus.mfa.runtime.MfaBuildTimeConfig;
import io.quarkus.mfa.runtime.MfaIdentityProvider;
import io.quarkus.mfa.runtime.MfaRecorder;
import io.quarkus.vertx.http.deployment.VertxWebRouterBuildItem;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;

@BuildSteps(onlyIf = QuarkusMfaProcessor.IsEnabled.class)
class QuarkusMfaProcessor {

    private static final String FEATURE = "mfa";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    public void myBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder();
        builder.addBeanClass(MfaIdentityProvider.class);
        additionalBeans.produce(builder.build());
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    public void initPermissions(MfaRecorder recorder, MfaBuildTimeConfig mfaBuildTimeConfig,
            HttpBuildTimeConfig httpBuildTimeConfig) {
        recorder.initPermissions(mfaBuildTimeConfig, httpBuildTimeConfig);

    }

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    public void setup(MfaRecorder recorder, MfaBuildTimeConfig mfaBuildTimeConfig,
            VertxWebRouterBuildItem vertxWebRouterBuildItem, BeanContainerBuildItem beanContainerBuildItem) {
        recorder.setupRoutes(beanContainerBuildItem.getValue(), mfaBuildTimeConfig, vertxWebRouterBuildItem.getHttpRouter());
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    void initMfaAuth(MfaRecorder recorder, MfaBuildTimeConfig mfaBuildTimeConfig,
            BuildProducer<SyntheticBeanBuildItem> syntheticBeans) {
        syntheticBeans.produce(SyntheticBeanBuildItem.configure(MfaAuthenticationMechanism.class).unremovable()
                .types(HttpAuthenticationMechanism.class).setRuntimeInit().scope(Singleton.class)
                .supplier(recorder.setupMfaAuthenticationMechanism(mfaBuildTimeConfig)).done());
    }

    public static class IsEnabled implements BooleanSupplier {
        MfaBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled;
        }
    }
}
