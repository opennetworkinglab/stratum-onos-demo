/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.stratumproject.fabricdemo.pipeconf;

import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.driver.DriverAdminService;
import org.onosproject.net.driver.DriverProvider;
import org.onosproject.net.pi.model.*;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabricdemo.AppConstants;

import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.*;

/**
 * Component that builds and register the pipeconf at app activation.
 */
@Component(immediate = true, service = PipeconfLoader.class)
public final class PipeconfLoader {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String BMV2_P4INFO_PATH = "/p4c-out/bmv2/p4info.txt";
    private static final String BMV2_JSON_PATH = "/p4c-out/bmv2/bmv2.json";
    private static final String BMV2_CPU_PORT_PATH = "/p4c-out/bmv2/cpu_port.txt";

    private static final String FPM_P4INFO_PATH = "/p4c-out/fpm/p4info.txt";
    private static final String FPM_BIN_PATH = "/p4c-out/fpm/pipeline_config.bin";
    private static final String FPM_CPU_PORT_PATH = "/p4c-out/fpm/cpu_port.txt";

    private static final String TOFINO_BIN_PATH = "/p4c-out/tofino-%s/pipe/tofino.bin";
    private static final String TOFINO_CTX_PATH = "/p4c-out/tofino-%s/pipe/context.json";
    private static final String TOFINO_P4INFO_PATH = "/p4c-out/tofino-%s/p4info.txt";
    private static final String TOFINO_CPU_PORT_PATH = "/p4c-out/tofino-%s/cpu_port.txt";

    private static final Collection<String> PIPECONF_POSTFIXES = Arrays.asList("bmv2", "fpm", "mavericks", "montara");
    private static final Collection<String> TOFINO_PROFILES = Arrays.asList("mavericks", "montara");


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DriverAdminService driverAdminService;

    @Activate
    public void activate() {
        PIPECONF_POSTFIXES.forEach(postfix -> {
            final PiPipeconfId pipeconfId = new PiPipeconfId(AppConstants.APP_NAME + "." + postfix);
            // Registers the pipeconf at component activation.
            if (pipeconfService.getPipeconf(pipeconfId).isPresent()) {
                // Remove first if already registered, to support reloading of the
                // pipeconf.
                pipeconfService.unregister(pipeconfId);
            }
        });


        removePipeconfDrivers();
        try {
            pipeconfService.register(buildBmv2Pipeconf());
            pipeconfService.register(buildFpmPipeconf());
            for (String profile : TOFINO_PROFILES) {
                pipeconfService.register(buildTofinoPipeconfs(profile));
            }
        } catch (P4InfoParserException e) {
            log.error("Unable to register pipeconf" + AppConstants.APP_NAME, e);
        }
    }

    @Deactivate
    public void deactivate() {
        // Do nothing.
    }

    private PiPipeconf buildBmv2Pipeconf() throws P4InfoParserException {

        final PiPipeconfId pipeconfId = new PiPipeconfId(AppConstants.APP_NAME + ".bmv2");
        final URL p4InfoUrl = PipeconfLoader.class.getResource(BMV2_P4INFO_PATH);
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);

        return DefaultPiPipeconf.builder()
                .withId(pipeconfId)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(BMV2_JSON,
                        PipeconfLoader.class.getResource(BMV2_JSON_PATH))
                .addExtension(CPU_PORT_TXT,
                        PipeconfLoader.class.getResource(BMV2_CPU_PORT_PATH))
                .build();
    }

    private PiPipeconf buildFpmPipeconf() throws P4InfoParserException {
        final PiPipeconfId pipeconfId = new PiPipeconfId(AppConstants.APP_NAME + ".fpm");
        final URL p4InfoUrl = PipeconfLoader.class.getResource(FPM_P4INFO_PATH);
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);

        return DefaultPiPipeconf.builder()
                .withId(pipeconfId)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(STRATUM_FPM_BIN,
                        PipeconfLoader.class.getResource(FPM_BIN_PATH))
                .addExtension(CPU_PORT_TXT,
                        PipeconfLoader.class.getResource(FPM_CPU_PORT_PATH))
                .build();
    }

    private PiPipeconf buildTofinoPipeconfs(String profile) throws P4InfoParserException {
        final PiPipeconfId pipeconfId = new PiPipeconfId(AppConstants.APP_NAME + "." + profile);
        final URL p4InfoUrl = PipeconfLoader.class.getResource(String.format(TOFINO_P4INFO_PATH, profile));
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);

        return DefaultPiPipeconf.builder()
                .withId(pipeconfId)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(TOFINO_BIN,
                        PipeconfLoader.class.getResource(String.format(TOFINO_BIN_PATH, profile)))
                .addExtension(TOFINO_CONTEXT_JSON,
                        PipeconfLoader.class.getResource(String.format(TOFINO_CTX_PATH, profile)))
                .addExtension(CPU_PORT_TXT,
                        PipeconfLoader.class.getResource(String.format(TOFINO_CPU_PORT_PATH, profile)))
                .build();
    }

    private void removePipeconfDrivers() {
        List<DriverProvider> driverProvidersToRemove = driverAdminService
                .getProviders().stream()
                .filter(p -> p.getDrivers().stream()
                        .anyMatch(d -> d.name().contains(AppConstants.APP_NAME)))
                .collect(Collectors.toList());

        if (driverProvidersToRemove.isEmpty()) {
            return;
        }

        log.info("Found {} outdated drivers for pipeconf '{}.*', removing...",
                 driverProvidersToRemove.size(), AppConstants.APP_NAME);

        driverProvidersToRemove.forEach(driverAdminService::unregisterProvider);
    }
}
