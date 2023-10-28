package src.controll;

import jpcap.packet.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class PacketAnalyze {
    Packet packet;

    public PacketAnalyze(Packet packet) {
        this.packet = packet;
    }



    public Map<String, String> analyze() {

        Map<String, String> message = new HashMap<>();

        message.putAll(analyzeEthernetPacket());

        if (packet instanceof jpcap.packet.Packet) {

            if (packet.getClass().equals(Packet.class))
                message.put("协议类型", "未知");
             else  if (packet.getClass().equals(TCPPacket.class))
                message.putAll(analyzeTCPPacket());
            else if (packet.getClass().equals(UDPPacket.class))
                message.putAll(analyzeUDPPacket());
        } else
            message.put("协议类型", "");

        return message;

    }


    private Map<String, String> analyzeUDPPacket() {
        // UDP数据报,UDPPacket类继承 IPPacket类;
        UDPPacket udpPacket = (UDPPacket) packet;
        return new HashMap<String, String>() {{
            put("UDP报文首部", udpPacket.toString());
            put("DF", String.valueOf(udpPacket.dont_frag));
            put("MF", String.valueOf(udpPacket.more_frag));
            put("片偏移", String.valueOf(udpPacket.offset));
            put("标识", String.valueOf(udpPacket.ident));
            put("协议类型", "UDP");
            put("源端口src_port", String.valueOf(udpPacket.src_port));
            put("目的端口dst_port", String.valueOf(udpPacket.dst_port));
            put("UDP报文长度length", String.valueOf(udpPacket.length));
            put("源IP", String.valueOf(udpPacket.src_ip));
            put("目的IP", String.valueOf(udpPacket.dst_ip));
        }};
    }

    private Map<String, String> analyzeTCPPacket() {
        TCPPacket tcpPacket = (TCPPacket) packet;// 将 TCPPacket类转成 IPPacket类;
        return new HashMap<String, String>() {{
            put("TCP报文首部", tcpPacket.toString());
            put("DF", String.valueOf(tcpPacket.dont_frag));
            put("MF", String.valueOf(tcpPacket.more_frag));
            put("片偏移", String.valueOf(tcpPacket.offset));
            put("标识", String.valueOf(tcpPacket.ident));
            put("协议类型", "TCP");
            put("源端口", String.valueOf(tcpPacket.src_port));
            put("目的端口", String.valueOf(tcpPacket.dst_port));
            put("seq", String.valueOf(tcpPacket.sequence));
            put("ACK", String.valueOf(tcpPacket.ack));
            put("ack", String.valueOf(tcpPacket.ack_num));
            put("报文长度", String.valueOf(tcpPacket.length));
            put("源IP", String.valueOf(tcpPacket.src_ip));
            put("目的IP", String.valueOf(tcpPacket.dst_ip));
        }};
    }

    private Map<String, String> analyzeEthernetPacket() {
        //以太帧
        EthernetPacket dataLink = (EthernetPacket) packet.datalink;
        return new HashMap<String, String>() {{
            put("以太帧首部", dataLink.toString());// 描述以太帧的字符串
            put("源mac地址", dataLink.getSourceAddress());// 源mac地址
            put("目的mac地址", dataLink.getDestinationAddress());// 目的mac地址
            put("帧类型", String.valueOf(dataLink.frametype));// 帧类型
        }};
    }



}
