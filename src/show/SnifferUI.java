package src.show;

import jpcap.NetworkInterface;
import src.controll.NetworkCard;
import src.controll.PacketCapture;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Map;

public class SnifferUI extends JFrame {
    private JPanel mainPanel;
    private JPanel headerPanel;
    private JPanel bodyPanel;
    private JPanel formPanel;
    private JLabel deviceSelectLabel;
    private JComboBox devicesComboBox;
    private JTable packetsTable;
    private JScrollPane tableScrollPanel;
    private JTextArea detailTextArea;
    private JLabel protocolLabel;
    private JComboBox protocolComboBox;

    private JButton startButton;
    private JButton stopButton;

    private JPanel detailPanel;
    private JScrollPane detailScrollPanel;

    //抓包
    PacketCapture packetCapture;

    Thread run;

    Thread count;
    //网卡
    NetworkInterface[] devices;


    String[] tableHeader = {"序号", "状态", "源IP", "目的IP", "协议类型", "时间"};

    DefaultTableModel tableModel;
    //详细信息
    Map<String, String> detail;
    //协议
    String[] protocolTypes = {"全部", "TCP", "UDP", "其他"};

    Map<String, String> filter;

    public SnifferUI() {
        filter = new HashMap<>();
        packetCapture = new PacketCapture();
        run = new Thread(packetCapture);

        devices = NetworkCard.getNetworkCards();
        tableModel = new DefaultTableModel(new Object[][]{}, tableHeader);

        packetCapture.setTableModel(tableModel);
        for (int i = 0; i < devices.length; i++) {
            NetworkInterface device = devices[i];
            devicesComboBox.addItem( i + ". " + device.description);
        }
        if (devices.length >= 3) {
            devicesComboBox.setSelectedIndex(2);
        } else devicesComboBox.setSelectedIndex(0);

        for (int i = 0; i < protocolTypes.length; i++) {
            protocolComboBox.addItem(protocolTypes[i]);
        }
        protocolComboBox.setSelectedIndex(0);

        devicesComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                }
            }
        });

        //列表
        packetsTable.setModel(tableModel);

        packetsTable.setRowHeight(40);
        detailTextArea.setDisabledTextColor(Color.black);

        //详细信息
        packetsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    int row = packetsTable.rowAtPoint(e.getPoint());
                    detail = packetCapture.getPacketsDetails().get(row);
                    detailTextArea.setText("");
                    for (Map.Entry<String, String> entry : detail.entrySet()) {
                        detailTextArea.append(entry.getKey() +" : ");
                        detailTextArea.append(entry.getValue() + '\n');
                    }
                }
            }
        });

        //开始
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (run.getState() != Thread.State.TERMINATED) {
                    run.stop();
                }
                packetCapture.clearList();
                packetCapture.setFilter(filter);
                packetCapture.setDevice(devices[devicesComboBox.getSelectedIndex()]);
                run = new Thread(packetCapture);
                run.start();
            }
        });
        //停止
        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (run.getState() == Thread.State.RUNNABLE) {
                    run.stop();
                }
            }
        });

        //协议
        protocolComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    filter.put("协议类型", String.valueOf(protocolComboBox.getSelectedItem()));
                }
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("SnifferUI");
        frame.setBounds(350, 50, 1200, 800);
        frame.setContentPane(new SnifferUI().mainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);


    }

}
