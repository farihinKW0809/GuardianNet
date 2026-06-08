from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub

import time
import math
import json
import os
import joblib
import pandas as pd
import requests
from collections import Counter


class GuardianNetMVP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(GuardianNetMVP, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        self.prev_packets = {}
        self.prev_time = {}
        self.flow_deltas = {}

        self.agentA_result = {}
        self.agentB_result = {}

        self.entropy_window = 5
        self.llm_last_call = {}
        self.llm_cooldown = 30

        self.ollama_url = "http://localhost:11434/api/generate"
        self.ollama_model = "llama3.2"

        self.dataset_file = "guardian_dataset.csv"
        self.current_label = os.getenv("LABEL", "0")

        model_path = os.path.expanduser("~/knn_model.pkl")
        if os.path.exists(model_path):
            self.knn_model = joblib.load(model_path)
            self.logger.info("KNN model loaded from %s", model_path)
        else:
            self.knn_model = None
            self.logger.warning("KNN model not found at %s", model_path)

        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info(
            "GuardianNet KNN Agent A + Entropy Agent B + LLM Agent C started"
        )

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("Switch connected: %s", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Register datapath %s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)

            hub.sleep(2)

    def entropy(self, values):
        if not values:
            return 0.0
        counts = Counter(values)
        total = float(len(values))
        result = 0.0
        for count in counts.values():
            p = count / total
            result -= p * math.log(p, 2)
        return result

    def detect_agent_a_knn(self, flow_id, packet_count, byte_count, duration):
        now = time.time()

        old_pkt = self.prev_packets.get(flow_id, packet_count)
        old_time = self.prev_time.get(flow_id, now)

        delta_pkt = packet_count - old_pkt
        delta_t = max(now - old_time, 1)
        pps = delta_pkt / delta_t

        self.prev_packets[flow_id] = packet_count
        self.prev_time[flow_id] = now

        self.logger.info(
            "[AGENT A] flow=%s total=%s delta=%s pps=%.2f",
            flow_id, packet_count, delta_pkt, pps
        )

        if self.knn_model is None:
            self.agentA_result[flow_id] = 0
            self.logger.warning("[AGENT A] KNN model not loaded")
            return delta_pkt

        try:
            features = pd.DataFrame(
                [[packet_count, byte_count, duration]],
                columns=["packet_count", "byte_count", "duration"]
            )

            prediction = int(self.knn_model.predict(features)[0])

            self.agentA_result[flow_id] = prediction

            self.logger.info(
                "[AGENT A] KNN prediction flow=%s -> %s",
                flow_id, prediction
            )

            if prediction == 1:
                self.logger.warning(
                    "[AGENT A] DDoS suspected by KNN on flow=%s",
                    flow_id
                )

        except Exception as e:
            self.agentA_result[flow_id] = 0
            self.logger.error("[AGENT A] KNN error: %s", str(e))

        return delta_pkt

    def detect_agent_b(self, flow_id, delta_pkt):
        history = self.flow_deltas.setdefault(flow_id, [])
        history.append(delta_pkt)
        history[:] = history[-self.entropy_window:]

        if len(history) < self.entropy_window:
            self.agentB_result[flow_id] = 0
            return

        total_delta = sum(history)
        non_zero_count = sum(1 for x in history if x > 0)
        avg_delta = total_delta / float(len(history))
        quantized = [int(x / 5) for x in history]
        ent = self.entropy(quantized)

        self.logger.info(
            "[AGENT B] flow=%s deltas=%s avg=%.2f entropy=%.4f non_zero=%s",
            flow_id, history, avg_delta, ent, non_zero_count
        )

        if total_delta >= 10 and non_zero_count >= 3 and avg_delta >= 1 and avg_delta < 20 and ent < 1.0:
            self.agentB_result[flow_id] = 1
            self.logger.warning(
                "[AGENT B] Slow Poisoning suspected on flow=%s",
                flow_id
            )
        else:
            self.agentB_result[flow_id] = 0

    def agent_c_decision(self, flow_id):
        a = self.agentA_result.get(flow_id, 0)
        b = self.agentB_result.get(flow_id, 0)

        if a == 0 and b == 0:
            return

        now = time.time()
        if now - self.llm_last_call.get(flow_id, 0) < self.llm_cooldown:
            return
        self.llm_last_call[flow_id] = now

        prompt = (
            "You are GuardianNet Agent C.\n"
            f"Flow ID: {flow_id}\n"
            f"Agent A KNN result: {a}\n"
            f"Agent B entropy result: {b}\n"
            "Rules:\n"
            "- A=1 and B=0 means DDoS.\n"
            "- A=0 and B=1 means Slow Poisoning.\n"
            "- A=1 and B=1 means Multi-stage Attack.\n"
            "- A=0 and B=0 means Normal.\n"
            "Return ONLY JSON with keys: attack_type, malicious_flow, reason."
        )

        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "format": "json",
            "stream": False
        }

        try:
            resp = requests.post(self.ollama_url, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            raw = data.get("response", "{}").strip()

            try:
                result = json.loads(raw)
            except Exception:
                result = {
                    "attack_type": "Unknown",
                    "malicious_flow": flow_id,
                    "reason": raw
                }

            attack_type = result.get("attack_type", "Unknown")
            reason = result.get("reason", "")

            self.logger.warning(
                "[AGENT C] FINAL DECISION flow=%s -> %s | reason=%s",
                flow_id, attack_type, reason
            )

        except Exception as e:
            self.logger.error("[AGENT C] LLM error for flow=%s: %s", flow_id, str(e))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            match = stat.match
            src = match.get("eth_src")
            dst = match.get("eth_dst")

            if not src or not dst:
                continue

            flow_id = "%s->%s" % (src, dst)

            self.logger.info(
                "Flow stat %s packets=%s bytes=%s duration=%s",
                flow_id, stat.packet_count, stat.byte_count, stat.duration_sec
            )

            duration = max(stat.duration_sec, 1)

            delta_pkt = self.detect_agent_a_knn(
                flow_id,
                stat.packet_count,
                stat.byte_count,
                duration
            )

            pps = float(delta_pkt) / float(duration)

            self.detect_agent_b(flow_id, delta_pkt)
            self.agent_c_decision(flow_id)

            with open(self.dataset_file, "a") as f:
                f.write(
                    "%s,%s,%s,%s,%.4f,%s\n" % (
                        stat.packet_count,
                        stat.byte_count,
                        duration,
                        delta_pkt,
                        pps,
                        self.current_label
                    )
                )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
                eth_src=src
            )
            self.add_flow(dp, 1, match, actions, idle_timeout=20)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        dp.send_msg(out)
