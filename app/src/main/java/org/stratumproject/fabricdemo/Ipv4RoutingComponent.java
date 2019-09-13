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

package org.stratumproject.fabricdemo;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.SetMultimap;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.*;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.*;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.routeservice.*;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabricdemo.common.FabricDeviceConfig;
import org.stratumproject.fabricdemo.common.Utils;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;

/**
 * App component that configures devices to provide IPv4 routing capabilities
 * across the whole fabric.
 */
@Component(immediate = true)
public class Ipv4RoutingComponent {

    private static final Logger log = LoggerFactory.getLogger(Ipv4RoutingComponent.class);

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;

    private final HostListener hostListener = new InternalHostListener();
    private final LinkListener linkListener = new InternalLinkListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final RouteListener routeListener = new InternalRouteListener();

    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private RouteService routeService;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        hostService.addListener(hostListener);
        linkService.addListener(linkListener);
        deviceService.addListener(deviceListener);
        routeService.addListener(routeListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, AppConstants.INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        linkService.removeListener(linkListener);
        deviceService.removeListener(deviceListener);
        routeService.removeListener(routeListener);

        log.info("Stopped");
    }

    /**
     * Sets up the "My Station" table for the given device using the
     * myStationMac address found in the config.
     * <p>
     * This method will be called at component activation for each device
     * (switch) known by ONOS, and every time a new device-added event is
     * captured by the InternalDeviceListener defined below.
     *
     * @param deviceId the device ID
     */
    private void setUpMyStationTable(DeviceId deviceId) {

        log.info("Adding My Station rules to {}...", deviceId);

        final MacAddress myStationMac = getMyStationMac(deviceId);

        // HINT: in our solution, the My Station table matches on the *ethernet
        // destination* and there is only one action called *NoAction*, which is
        // used as an indication of "table hit" in the control block.

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        final String tableId = "ingress.my_station_table";

        final PiCriterion match = PiCriterion.builder()
                .matchTernary(
                        PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        myStationMac.toBytes(),
                        MacAddress.EXACT_MASK.toBytes())
                .build();

        // Creates an action which do *NoAction* when hit.
        final PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("ingress.set_l3_admit"))
                .build();

        final FlowRule myStationRule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        flowRuleService.applyFlowRules(myStationRule);
    }

    /**
     * Creates an ONOS SELECT group for the routing table to provide ECMP
     * forwarding for the given collection of next hop MAC addresses. ONOS
     * SELECT groups are equivalent to P4Runtime action selector groups.
     * <p>
     * This method will be called by the routing policy methods below to insert
     * groups in the L3 table
     *
     * @param nextHopMacToPorts the collection of mac addresses of next hops
     * @param deviceId          the device where the group will be installed
     * @return a SELECT group
     */
    private GroupDescription createNextHopGroup(
            int groupId,
            SetMultimap<MacAddress, PortNumber> nextHopMacToPorts,
            DeviceId deviceId) {

        String actionProfileId = "ingress.l3_fwd.wcmp_action_profile";

        final List<PiAction> actions = Lists.newArrayList();

        // Build one "set next hop" action for each next hop
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        final String tableId = "ingress.l3_fwd.l3_fwd_table";
        for (MacAddress nextHopMac : nextHopMacToPorts.keySet()) {
            for (PortNumber port : nextHopMacToPorts.get(nextHopMac)) {
                final PiAction action = PiAction.builder()
                        .withId(PiActionId.of("ingress.l3_fwd.set_nexthop"))
                        .withParameter(new PiActionParam(
                                PiActionParamId.of("port"),
                                (short) port.toLong()))
                        .withParameter(new PiActionParam(
                                PiActionParamId.of("smac"),
                                getMyStationMac(deviceId).toBytes()))
                        .withParameter(new PiActionParam(
                                PiActionParamId.of("dmac"),
                                nextHopMac.toBytes()))
                        .withParameter(new PiActionParam(
                                PiActionParamId.of("dst_vlan"),
                                1))
                        .build();

                actions.add(action);
            }
        }

        if (actions.isEmpty()) {
            return null;
        }

        return Utils.buildSelectGroup(
                deviceId, tableId, actionProfileId, groupId, actions, appId);
    }

    /**
     * Creates a routing flow rule that matches on the given IPv4 prefix and
     * executes the given group ID (created before).
     *
     * @param deviceId the device where flow rule will be installed
     * @param ipPrefix the IPv4 prefix
     * @param groupId  the group ID
     * @return a flow rule
     */
    private FlowRule createRoutingRule(DeviceId deviceId, Ip4Prefix ipPrefix,
                                       int groupId) {

        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        final String tableId = "ingress.l3_fwd.l3_fwd_table";
        final PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("local_metadata.vrf_id"), 0)
                .matchLpm(
                        PiMatchFieldId.of("hdr.ipv4_base.dst_addr"),
                        ipPrefix.address().toOctets(),
                        ipPrefix.prefixLength())
                .build();

        final PiTableAction action = PiActionProfileGroupId.of(groupId);

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            DeviceId deviceId = host.location().deviceId();
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, host.location().port());
                setUpHostRules(deviceId, host);
            });
        }
    }

    /**
     * Listener of link events, which triggers configuration of routing rules to
     * forward packets across the fabric, i.e. from leaves to spines and vice
     * versa.
     * <p>
     * Reacting to link events instead of device ones, allows us to make sure
     * all device are always configured with a topology view that includes all
     * links, e.g. modifying an ECMP group as soon as a new link is added. The
     * downside is that we might be configuring the same device twice for the
     * same set of links/paths. However, the ONOS core treats these cases as a
     * no-op when the device is already configured with the desired forwarding
     * state (i.e. flows and groups)
     */
    class InternalLinkListener implements LinkListener {

        @Override
        public boolean isRelevant(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                case LINK_UPDATED:
                case LINK_REMOVED:
                    break;
                default:
                    return false;
            }
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            return mastershipService.isLocalMaster(srcDev) ||
                    mastershipService.isLocalMaster(dstDev);
        }

        @Override
        public void event(LinkEvent event) {
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();

            // Link events are bi-directional, i.e. fire twice
            if (mastershipService.isLocalMaster(srcDev)) {
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
                            event.type(), srcDev, srcDev, dstDev);
                    setUpFabricRoutes(srcDev, dstDev);
                });
            }
        }
    }

    /**
     * Listener of device events which triggers configuration of the My Station
     * table.
     */
    class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED:
                case DEVICE_ADDED:
                    break;
                default:
                    return false;
            }
            // Process device event if this controller instance is the master
            // for the device and the device is available.
            DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId) &&
                    deviceService.isAvailable(event.subject().id());
        }

        @Override
        public void event(DeviceEvent event) {
            mainComponent.getExecutorService().execute(() -> {
                DeviceId deviceId = event.subject().id();
                log.info("{} event! device id={}", event.type(), deviceId);
                setUpDevice(deviceId);
            });
        }
    }

    /**
     * Listener of route events, which triggers configuration of routing rules to
     * forward packets to a specific next hop.
     */
    private class InternalRouteListener implements RouteListener {

        @Override
        public boolean isRelevant(RouteEvent event) {
            switch (event.type()) {
                case ROUTE_ADDED:
                case ROUTE_REMOVED:
                    break;
                case ROUTE_UPDATED:
                case ALTERNATIVE_ROUTES_CHANGED:
                default:
                    return false;
            }
            return true;
        }

        @Override
        public void event(RouteEvent event) {
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! {}", event.type(), event.subject());
                setUpRouteToDevices(event.subject(), event.type());
            });
        }
    }

    /**
     * Set up a route to all devices.
     *
     * @param route the route
     */
    private void setUpRouteToDevices(ResolvedRoute route, RouteEvent.Type op) {
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    if (isSpine(deviceId)) {
                        setUpRouteRuleToSpine(deviceId, route, op);
                    } else {
                        setUpRouteRuleToLeaf(deviceId, route, op);
                    }
                });
    }

    /**
     * Installs a route rule for a leaf.
     * If the next hop connect to the leaf, route to the next hop directly.
     * If the next hop does not connect to the leaf, route to spines by using the ECMP group.
     *
     * @param deviceId the leaf device id
     * @param route the route
     * @param op the operation, can be ROUTE_ADDED or ROUTE_REMOVED
     */
    private void setUpRouteRuleToLeaf(DeviceId deviceId, ResolvedRoute route, RouteEvent.Type op) {
        HostId nextHopId = HostId.hostId(route.nextHopMac(), route.nextHopVlan());
        Host nextHop = hostService.getHost(nextHopId);
        if (nextHop == null || nextHop.location() == null) {
            log.warn("Cannot find next hop {}, ignore it", route.nextHop());
            return;
        }
        int groupId;
        if (nextHop.location().deviceId().equals(deviceId)) {
            // Next hop host connect to this device
            groupId = macToGroupId(nextHop.mac());
        } else {
            // Next hop host does not connect to this device, need to send packet through spines
            groupId = DEFAULT_ECMP_GROUP_ID;
        }
        FlowRule routeRule = createRoutingRule(deviceId, route.prefix().getIp4Prefix(), groupId);
        if (op == RouteEvent.Type.ROUTE_ADDED) {
            flowRuleService.applyFlowRules(routeRule);
        } else {
            flowRuleService.removeFlowRules(routeRule);
        }
    }

    /**
     * Installs a route rule for a spine.
     * The packet will be routed to the leaf which connect to the next hop.
     *
     * @param deviceId the spine device id
     * @param route the route
     * @param op the operation, can be ROUTE_ADDED or ROUTE_REMOVED
     */
    private void setUpRouteRuleToSpine(DeviceId deviceId, ResolvedRoute route, RouteEvent.Type op) {
        HostId nextHopId = HostId.hostId(route.nextHopMac(), route.nextHopVlan());
        Host nextHop = hostService.getHost(nextHopId);
        if (nextHop == null || nextHop.location() == null) {
            log.warn("Cannot find next hop {}, ignore it", route.nextHop());
            return;
        }
        // Find the device mac which connect to the next hop host.
        MacAddress leafMac = getMyStationMac(nextHop.location().deviceId());
        int groupId = macToGroupId(leafMac);
        FlowRule routeRule = createRoutingRule(deviceId, route.prefix().getIp4Prefix(), groupId);
        if (op == RouteEvent.Type.ROUTE_ADDED) {
            flowRuleService.applyFlowRules(routeRule);
        } else {
            flowRuleService.removeFlowRules(routeRule);
        }
    }


    //--------------------------------------------------------------------------
    // ROUTING POLICY METHODS
    //
    // Called by event listeners, these methods implement the actual routing
    // policy, responsible of computing paths and creating ECMP groups.
    //--------------------------------------------------------------------------

    /**
     * Sets up the given device with the necessary rules to route packets to the
     * given host.
     *
     * @param deviceId deviceId the device ID
     * @param host     the host
     */
    private void setUpHostRules(DeviceId deviceId, Host host) {

        // Get all IPv4 addresses associated to this host. In this tutorial we
        // use hosts with only 1 IPv4 address.
        final Collection<Ip4Address> hostIpv4Addrs = host.ipAddresses().stream()
                .filter(IpAddress::isIp4)
                .map(IpAddress::getIp4Address)
                .collect(Collectors.toSet());

        if (hostIpv4Addrs.isEmpty()) {
            // Ignore.
            log.debug("No IPv4 addresses for host {}, ignore", host.id());
            return;
        } else {
            log.info("Adding routes on {} for host {} [{}]",
                    deviceId, host.id(), hostIpv4Addrs);
        }

        // Create an ECMP group with only one member, where the group ID is
        // derived from the host MAC.
        final MacAddress hostMac = host.mac();
        final PortNumber port = host.location().port();
        int groupId = macToGroupId(hostMac);

        final SetMultimap<MacAddress, PortNumber> macToPorts = HashMultimap.create();
        macToPorts.put(hostMac, port);

        final GroupDescription group = createNextHopGroup(
                groupId, macToPorts, deviceId);

        // Map each host IPV4 address to corresponding /32 prefix and obtain a
        // flow rule that points to the group ID. In this tutorial we expect
        // only one flow rule per host.
        final List<FlowRule> flowRules = hostIpv4Addrs.stream()
                .map(IpAddress::toIpPrefix)
                .filter(IpPrefix::isIp4)
                .map(IpPrefix::getIp4Prefix)
                .map(prefix -> createRoutingRule(deviceId, prefix, groupId))
                .collect(Collectors.toList());

        // Helper function to install flows after groups, since here flows
        // points to the group and P4Runtime enforces this dependency during
        // write operations.
        insertInOrder(group, flowRules);
    }

    /**
     * Set up routes on a given device to forward packets across the fabric,
     * making a distinction between spines and leaves.
     *
     * @param srcDev the device ID the routes are configured on.
     * @param dstDev the device ID the routes are configured to.
     */
    private void setUpFabricRoutes(DeviceId srcDev, DeviceId dstDev) {
        if (isSpine(srcDev)) {
            setUpSpineRoute(srcDev, dstDev);
        } else {
            setUpLeafRoutes(srcDev);
        }
    }

    /**
     * Insert routing rules on the given spine switch, matching on leaf
     * interface subnets and forwarding packets to the corresponding leaf.
     *
     * @param spineId the spine device ID
     */
    private void setUpSpineRoute(DeviceId spineId, DeviceId leafId) {
        log.info("Adding up spine route on {} to {}", spineId, leafId);

        if (!isSpine(spineId)) {
            log.error("setUpSpineRoute() called for a source device that is not a spine: {}", spineId);
            return;
        }

        if (!isLeaf(leafId)) {
            log.error("setUpSpineRoute() called for a destination device that is not a leaf: {}", leafId);
            return;
        }

        final MacAddress leafMac = getMyStationMac(leafId);
        final Set<Ip4Prefix> subnetsToRoute = getInterfaceIpv4Prefixes(leafId);

        // Create group
        int groupId = macToGroupId(leafMac);

        final SetMultimap<MacAddress, PortNumber> macToPorts = HashMultimap.create();
        getPortsToNextHop(spineId, leafMac)
                .forEach(p -> macToPorts.put(leafMac, p));

        if (macToPorts.values().isEmpty()) {
            // No routes to install.
            return;
        }

        GroupDescription group = createNextHopGroup(
                groupId, macToPorts, spineId);

        List<FlowRule> flowRules = subnetsToRoute.stream()
                .map(subnet -> createRoutingRule(spineId, subnet, groupId))
                .collect(Collectors.toList());

        insertInOrder(group, flowRules);

        // Install resolved routes from route store
        routeService.getRouteTables().stream()
                .map(routeService::getResolvedRoutes)
                .flatMap(Collection::stream)
                .forEach(resolvedRoute -> setUpRouteRuleToSpine(spineId, resolvedRoute, RouteEvent.Type.ROUTE_ADDED));
    }

    private Collection<PortNumber> getPortsToNextHop(DeviceId deviceId, MacAddress dstMac) {
        Set<Link> egressLinks = linkService.getDeviceEgressLinks(deviceId);
        Collection<PortNumber> ports = Lists.newArrayList();
        for (Link link : egressLinks) {
            // For each other switch directly connected to this.
            final DeviceId nextHopDevice = link.dst().deviceId();
            if (!dstMac.equals(getMyStationMac(nextHopDevice))) {
                // Not interested.
                continue;
            }
            // Get port of this device connecting to next hop.
            final PortNumber outPort = link.src().port();
            ports.add(outPort);
        }
        return ports;
    }

    /**
     * Insert routing rules on the given leaf switch, matching on interface
     * subnets associated to other leaves and forwarding packets the spines
     * using ECMP.
     *
     * @param leafId the leaf device ID
     */
    private void setUpLeafRoutes(DeviceId leafId) {
        log.info("Setting up leaf routes: {}", leafId);

        // Get the set of subnets (interface IPv4 prefixes) associated to other
        // leafs but not this one.
        Set<Ip4Prefix> subnetsToRouteViaSpines = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isLeaf)
                .filter(deviceId -> !deviceId.equals(leafId))
                .map(this::getInterfaceIpv4Prefixes)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        // Get myStationMac address of all spines.
        Set<MacAddress> spineMacs = stream(deviceService.getDevices())
                .map(Device::id)
                .filter(this::isSpine)
                .map(this::getMyStationMac)
                .collect(Collectors.toSet());

        final SetMultimap<MacAddress, PortNumber> macToPorts = HashMultimap.create();

        for (MacAddress spineMac : spineMacs) {
            getPortsToNextHop(leafId, spineMac)
                    .forEach(p -> macToPorts.put(spineMac, p));
        }

        if (macToPorts.values().isEmpty()) {
            log.info("There are NO spines attached to leaf {} :(", leafId);
            // No routes to install.
            return;
        }

        log.info("Found {} spines attached to leaf {}...",
                macToPorts.keySet().size(), leafId);
        for (MacAddress mac : macToPorts.keySet()) {
            log.info("{} -> {} via {} ports ({})",
                    leafId, mac, macToPorts.get(mac).size(), macToPorts.get(mac));
        }

        // Create an ECMP group to distribute traffic across all spines.
        final int groupId = DEFAULT_ECMP_GROUP_ID;
        final GroupDescription ecmpGroup = createNextHopGroup(
                groupId, macToPorts, leafId);

        // Generate a flow rule for each subnet pointing to the ECMP group.
        List<FlowRule> flowRules = subnetsToRouteViaSpines.stream()
                .map(subnet -> createRoutingRule(leafId, subnet, groupId))
                .collect(Collectors.toList());

        insertInOrder(ecmpGroup, flowRules);

        // Install resolved routes from route store
        routeService.getRouteTables().stream()
                .map(routeService::getResolvedRoutes)
                .flatMap(Collection::stream)
                .forEach(resolvedRoute -> setUpRouteRuleToLeaf(leafId, resolvedRoute, RouteEvent.Type.ROUTE_ADDED));
    }

    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Returns true if the given device has isSpine flag set to true in the
     * config, false otherwise.
     *
     * @param deviceId the device ID
     * @return true if the device is a spine, false otherwise
     */
    private boolean isSpine(DeviceId deviceId) {
        return getDeviceConfig(deviceId).map(FabricDeviceConfig::isSpine)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing isSpine config for " + deviceId));
    }

    /**
     * Returns true if the given device is not configured as spine.
     *
     * @param deviceId the device ID
     * @return true if the device is a leaf, false otherwise
     */
    private boolean isLeaf(DeviceId deviceId) {
        return !isSpine(deviceId);
    }

    /**
     * Returns the MAC address configured in the "myStationMac" property of the
     * given device config.
     *
     * @param deviceId the device ID
     * @return MyStation MAC address
     */
    private MacAddress getMyStationMac(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::myStationMac)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing myStationMac config for " + deviceId));
    }

    /**
     * Returns the config object for the given device.
     *
     * @param deviceId the device ID
     * @return device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns the set of interface IPv4 subnets (prefixes) configured for the
     * given device.
     *
     * @param deviceId the device ID
     * @return set of IPv4 prefixes
     */
    private Set<Ip4Prefix> getInterfaceIpv4Prefixes(DeviceId deviceId) {
        return interfaceService.getInterfaces().stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .map(Interface::ipAddressesList)
                .flatMap(Collection::stream)
                .map(InterfaceIpAddress::subnetAddress)
                .filter(IpPrefix::isIp4)
                .map(IpPrefix::getIp4Prefix)
                .collect(Collectors.toSet());
    }

    /**
     * Returns a 32 bit bit group ID from the given MAC address.
     *
     * @param mac the MAC address
     * @return an integer
     */
    private int macToGroupId(MacAddress mac) {
        return mac.hashCode() & 0x7fffffff;
    }

    /**
     * Inserts a new group, or if the group already exists, performs the required modifications.
     *
     * @param group new group
     */
    private synchronized void insertOrModifyGroup(GroupDescription group) {
        Group existing = groupService.getGroup(group.deviceId(), group.appCookie());
        if (existing == null) {
            groupService.addGroup(group);
            return;
        }

        groupService.setBucketsForGroup(group.deviceId(), group.appCookie(),
                group.buckets(), group.appCookie(), group.appId());
    }

    /**
     * Inserts the given groups and flow rules in order, groups first, then flow
     * rules. In P4Runtime, when operating on an indirect table (i.e. with
     * action selectors), groups must be inserted before table entries.
     *
     * @param group     the group
     * @param flowRules the flow rules depending on the group
     */
    private void insertInOrder(GroupDescription group, Collection<FlowRule> flowRules) {
        try {
            insertOrModifyGroup(group);
            // Wait for groups to be inserted.
            Thread.sleep(GROUP_INSERT_DELAY_MILLIS);
            flowRules.forEach(flowRuleService::applyFlowRules);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Sets up IPv4 routing on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(this::setUpDevice);
    }

    private void setUpDevice(DeviceId deviceId) {
        log.info("*** IPV4 ROUTING - Starting initial set up for {}...", deviceId);
        setUpMyStationTable(deviceId);
        hostService.getConnectedHosts(deviceId)
                .forEach(host -> setUpHostRules(deviceId, host));
    }
}
