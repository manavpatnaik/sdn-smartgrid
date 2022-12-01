import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib import dpid as dpid_lib
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
from ryu.lib.packet import arp


class ProjectController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}

    def add_flow2(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, src, dst, src_ip, dst_ip, actions):
        print(str(datapath)+":"+str(src)+"<->"+str(dst))

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        match = parser.OFPMatch(eth_src=src, eth_dst=dst,
                                eth_type=0x800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0, cookie_mask=0, table_id=0, command=ofproto_v1_3.OFPFC_ADD,
                                idle_timeout=0, hard_timeout=0, priority=10, buffer_id=ofproto_v1_3.OFP_NO_BUFFER, flags=ofproto_v1_3.OFPFF_SEND_FLOW_REM,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow2(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        # print "p"
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_ipv4:
            pkt_ipv4_src = pkt_ipv4.src
            pkt_ipv4_dst = pkt_ipv4.dst
            print(pkt_ipv4_src)
            print(pkt_ipv4_dst)
            print(src)
            print(dst)

            if dst in self.net:
                paths = nx.all_simple_paths(self.net, src, dst)
                print("Path0:")
                print(list(paths))
                path = nx.shortest_path(self.net, src, dst)
                print("Path1:")
                print(path)
                for next in path:
                    # print path.index(next)
                    index = path.index(next)
                    if index != 0 and index != len(path)-1:
                        out_port = self.net[next][path[index+1]]['port']
                        # print "out_port:"+str(out_port)
                        actions = [
                            datapath.ofproto_parser.OFPActionOutput(out_port)]
                        datapath = self.nodes[next]
                        self.add_flow(datapath, src, dst,
                                      pkt_ipv4_src, pkt_ipv4_dst, actions)
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                            actions=actions)
                        datapath.send_msg(out)

        if pkt_arp:
            # print "arp"
            # print src
            # print dst
            if src not in self.net:
                print(src)
                self.net.add_node(src)
                self.net.add_edge(dpid, src, {'port': msg.match['in_port']})
                self.net.add_edge(src, dpid)

            out_port = ofproto.OFPP_FLOOD
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)

            datapath.send_msg(out)

    @set_ev_cls(event.EventLinkAdd)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        for switch in switch_list:
            self.nodes[switch.dp.id] = switch.dp

        links_list = get_link(self.topology_api_app, None)

        links = [(link.src.dpid, link.dst.dpid, {
                  'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {
                  'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
