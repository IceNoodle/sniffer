package sniffer;

import java.io.IOException;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Vector;
import java.util.jar.Pack200.Packer;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.event.TreeModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import com.sun.xml.internal.bind.v2.runtime.reflect.Lister.Pack;
import com.sun.xml.internal.ws.api.model.wsdl.editable.EditableWSDLBoundFault;
import com.sun.xml.internal.ws.api.pipe.ThrowableContainerPropertySet;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import net.sourceforge.jpcap.util.TcpdumpWriter;

public class mysniffer {
	private final NetworkInterface[] devices;
	private String buf[];
	private boolean running;
	private JpcapCaptor jpcap;
	private Vector<Packet>v,tot;//tot��¼�ô�ץ�����ܵĽ����v��¼��ǰ��ʾ��ҳ��Ľ��
	private Vector<String>pwd;
	private DefaultTableModel model;
	private JTable jt=null;
	//���캯������ʼ����������
	public mysniffer(){
		running=false;
		v=new Vector<Packet>();
		tot=new Vector<Packet>();
		pwd=new Vector<String>();
		devices= JpcapCaptor.getDeviceList(); 
		buf=new String[devices.length];
		for(int i=0;i<devices.length;i++)buf[i]=devices[i].name;
	}
	//����ץ��
	public int work(int index){
		try {
			//����������Ϊ��������Ϊ����ģʽ
			jpcap=JpcapCaptor.openDevice(devices[index-1], 65536, true, 100);
			capThread(jpcap);
		} catch (IOException e) {
			return -1;
		}
		return 1;
	}
	//����ץ�����߳�
	private void capThread(final JpcapCaptor jpcap){
		java.lang.Runnable runner=new Runnable() {
			public void run() {
				while(running){
					jpcap.loopPacket(1, new testPacketReceiver());
				}
			}
		};
		new Thread(runner).start();
	}
	//��ץ���İ����д���
	class testPacketReceiver implements PacketReceiver{
		public void receivePacket(Packet packet){
			if(judge(packet)>=0){
				v.add(packet);//��ץ���İ���ӵ�v��tot����vector<packet>��ȥ���Դ���һ������
				tot.add(packet);
				changeTable(packet,0,false);//��ӵ�Jtable�����ȥ
			}
		}
	}
	//��ץ���İ���ӵ�JTabel��ȥ
	private void changeTable(Packet packet,int index,boolean useIndex){
		Object data[]=new Object[6];
		if(!useIndex)data[0]=String.valueOf(v.size());//����Ÿ�ֵ
		else data[0]=String.valueOf(index);
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//�������ڸ�ʽ
		df.format(new Date());
		data[1]=df.format(new Date());
		if(packet instanceof TCPPacket){
			TCPPacket tmp=(TCPPacket)packet;
			data[2]=tmp.src_ip;
			data[3]=tmp.dst_ip;
			data[4]="TCP";
			if(tmp.src_port==80||tmp.dst_port==80)data[4]="HTTP";
			data[5]=tmp.caplen;
		}
		if(packet instanceof UDPPacket){
			UDPPacket tmp=(UDPPacket)packet;
			data[2]=tmp.src_ip;
			data[3]=tmp.dst_ip;
			data[4]="UDP";
			if(tmp.src_port==80||tmp.dst_port==80)data[4]="HTTP";
			data[5]=tmp.caplen;
		}
		if(packet instanceof ARPPacket){
			ARPPacket tmp=(ARPPacket)packet;
			data[2]=tmp.getSenderProtocolAddress();
			data[3]=tmp.getTargetProtocolAddress();
			data[4]="ARP";
			data[5]=tmp.caplen;
		}
		if(packet instanceof ICMPPacket){
			ICMPPacket tmp=(ICMPPacket)packet;
			data[2]=tmp.src_ip;
			data[3]=tmp.dst_ip;
			data[4]="ICMP";
			data[5]=tmp.caplen;
		}
		model.addRow(data);
		jt.setModel(model);
	}
	//�б���ʲô��
	private int judge(Packet packet){	
		if(packet instanceof jpcap.packet.TCPPacket)return 1;
		else if(packet instanceof jpcap.packet.UDPPacket)return 2;
		else if(packet instanceof jpcap.packet.ARPPacket)return 3;
		else if(packet instanceof jpcap.packet.ICMPPacket)return 4;
		return 0;
	}
	//�԰�ͷ����Ϣ��ӵ�JTree��ȥ
	public void analyze(int index,JTree jtr){
		Packet packet=v.get(index);
		DefaultMutableTreeNode root=new DefaultMutableTreeNode("���ݰ�����");
		DatalinkPacket data=packet.datalink;
		if(data instanceof EthernetPacket){
			EthernetPacket ep=(EthernetPacket)data;
			DefaultMutableTreeNode linkLayer=new DefaultMutableTreeNode("������·��");
			linkLayer.add(new DefaultMutableTreeNode("ԴMAC:"+ep.getSourceAddress()));
			linkLayer.add(new DefaultMutableTreeNode("Ŀ��MAC:"+ep.getDestinationAddress()));
			root.add(linkLayer);
		}
		DefaultMutableTreeNode networkLayer=new DefaultMutableTreeNode("�����");
		if(packet instanceof IPPacket){
			IPPacket ipp=(IPPacket)packet;
			DefaultMutableTreeNode version=new DefaultMutableTreeNode("�汾��:IPV"+ipp.version);
			networkLayer.add(version);
			if(ipp.version==4){
				DefaultMutableTreeNode dFlag=new DefaultMutableTreeNode("Delay flag:"+ipp.d_flag);
				networkLayer.add(dFlag);
				DefaultMutableTreeNode tFlag=new DefaultMutableTreeNode("Through flag:"+ipp.t_flag);
				networkLayer.add(tFlag);
				DefaultMutableTreeNode rFlag=new DefaultMutableTreeNode("Reliability flag:"+ipp.r_flag);
				networkLayer.add(rFlag);
				DefaultMutableTreeNode tos=new DefaultMutableTreeNode("TOS:"+ipp.rsv_tos);
				networkLayer.add(tos);
				DefaultMutableTreeNode rsvFlag=new DefaultMutableTreeNode("Fragmentation Reservation flag:"+ipp.rsv_frag);
				networkLayer.add(rsvFlag);
				DefaultMutableTreeNode dontFlag=new DefaultMutableTreeNode("Don't fragment flag:"+ipp.dont_frag);
				networkLayer.add(dontFlag);
				DefaultMutableTreeNode moreFlag=new DefaultMutableTreeNode("More fragment flag:"+ipp.more_frag);
				networkLayer.add(moreFlag);
				DefaultMutableTreeNode offset=new DefaultMutableTreeNode("��ƫ��:"+ipp.offset);
				networkLayer.add(offset);
				DefaultMutableTreeNode id=new DefaultMutableTreeNode("��ʶ:"+ipp.ident);
				networkLayer.add(id);
				DefaultMutableTreeNode ttl=new DefaultMutableTreeNode("������:"+ipp.hop_limit);
				networkLayer.add(ttl);
				DefaultMutableTreeNode proto=new DefaultMutableTreeNode("Э��:"+ipp.protocol);
				networkLayer.add(proto);
				DefaultMutableTreeNode srcIp=new DefaultMutableTreeNode("ԴIP:"+ipp.src_ip);
				networkLayer.add(srcIp);
				DefaultMutableTreeNode dstIp=new DefaultMutableTreeNode("Ŀ��IP:"+ipp.dst_ip);
				networkLayer.add(dstIp);
			}else{
				DefaultMutableTreeNode cls=new DefaultMutableTreeNode("������:"+ipp.priority);
				networkLayer.add(cls);
				DefaultMutableTreeNode flowLabel=new DefaultMutableTreeNode("����ǩ:"+ipp.flow_label);
				networkLayer.add(flowLabel);
				DefaultMutableTreeNode nextHdr=new DefaultMutableTreeNode("��һ���ײ�:"+ipp.protocol);
				networkLayer.add(nextHdr);
				DefaultMutableTreeNode ttl=new DefaultMutableTreeNode("������:"+ipp.hop_limit);
				networkLayer.add(ttl);
				DefaultMutableTreeNode srcIp=new DefaultMutableTreeNode("ԴIP:"+ipp.src_ip);
				networkLayer.add(srcIp);
				DefaultMutableTreeNode dstIp=new DefaultMutableTreeNode("Ŀ��IP:"+ipp.dst_ip);
				networkLayer.add(dstIp);
			}
		}else if(packet instanceof ARPPacket){
			ARPPacket arpp=(ARPPacket)packet;
			DefaultMutableTreeNode arp=new DefaultMutableTreeNode("Э��:ARP");
			networkLayer.add(arp);
			DefaultMutableTreeNode hardType=new DefaultMutableTreeNode("Ӳ������:"+arpp.hardtype);
			networkLayer.add(hardType);
			DefaultMutableTreeNode proto=new DefaultMutableTreeNode("Э������:"+arpp.prototype);
			networkLayer.add(proto);
			DefaultMutableTreeNode hLen=new DefaultMutableTreeNode("Ӳ����ַ����:"+arpp.hlen);
			networkLayer.add(hLen);
			DefaultMutableTreeNode pLen=new DefaultMutableTreeNode("Э���ַ����:"+arpp.plen);
			networkLayer.add(pLen);
			DefaultMutableTreeNode op=new DefaultMutableTreeNode("������:"+arpp.operation);
			networkLayer.add(op);
			DefaultMutableTreeNode macSrc=new DefaultMutableTreeNode("ԴMAC:"+arpp.getSenderHardwareAddress());
			networkLayer.add(macSrc);
			DefaultMutableTreeNode ipSrc=new DefaultMutableTreeNode("ԴIP:"+arpp.getSenderProtocolAddress());
			networkLayer.add(ipSrc);
			DefaultMutableTreeNode macDst=new DefaultMutableTreeNode("Ŀ��MAC:"+arpp.getTargetHardwareAddress());
			networkLayer.add(macDst);
			DefaultMutableTreeNode ipDst=new DefaultMutableTreeNode("Ŀ��IP:"+arpp.getTargetProtocolAddress());
			networkLayer.add(ipDst);
		}else if(packet instanceof ICMPPacket){
			ICMPPacket icmpp=(ICMPPacket)packet;
			DefaultMutableTreeNode icmp=new DefaultMutableTreeNode("Э��:ICMP");
			networkLayer.add(icmp);
			DefaultMutableTreeNode type=new DefaultMutableTreeNode("����:"+icmpp.type);
			networkLayer.add(type);
			DefaultMutableTreeNode code=new DefaultMutableTreeNode("����:"+icmpp.code);
			networkLayer.add(code);
			DefaultMutableTreeNode check=new DefaultMutableTreeNode("У���:"+icmpp.checksum);
			networkLayer.add(check);
			DefaultMutableTreeNode id=new DefaultMutableTreeNode("��ʶ:"+icmpp.id);
			networkLayer.add(id);
			DefaultMutableTreeNode seq=new DefaultMutableTreeNode("���к�:"+icmpp.seq);
			networkLayer.add(seq);
		}
		DefaultMutableTreeNode transLayer=new DefaultMutableTreeNode("�����");
		if(packet instanceof TCPPacket){
			TCPPacket tcpp=(TCPPacket)packet;
			DefaultMutableTreeNode tcp=new DefaultMutableTreeNode("Э��:TCP");
			transLayer.add(tcp);
			DefaultMutableTreeNode srcPort=new DefaultMutableTreeNode("Դ�˿�:"+tcpp.src_port);
			transLayer.add(srcPort);
			DefaultMutableTreeNode dstPort=new DefaultMutableTreeNode("Ŀ�Ķ˿�:"+tcpp.dst_port);
			transLayer.add(dstPort);
			DefaultMutableTreeNode seq=new DefaultMutableTreeNode("���к�:"+tcpp.sequence);
			transLayer.add(seq);
			DefaultMutableTreeNode check=new DefaultMutableTreeNode("У���:"+tcpp.ack_num);
			transLayer.add(check);
			DefaultMutableTreeNode urg=new DefaultMutableTreeNode("urg:"+tcpp.urg);
			transLayer.add(urg);
			DefaultMutableTreeNode ack=new DefaultMutableTreeNode("ack:"+tcpp.ack);
			transLayer.add(ack);
			DefaultMutableTreeNode psh=new DefaultMutableTreeNode("psh:"+tcpp.psh);
			transLayer.add(psh);
			DefaultMutableTreeNode rst=new DefaultMutableTreeNode("rst:"+tcpp.rst);
			transLayer.add(rst);
			DefaultMutableTreeNode syn=new DefaultMutableTreeNode("syn:"+tcpp.syn);
			transLayer.add(syn);
			DefaultMutableTreeNode fin=new DefaultMutableTreeNode("fin:"+tcpp.fin);
			transLayer.add(fin);
			DefaultMutableTreeNode rsv1=new DefaultMutableTreeNode("rsv1:"+tcpp.rsv1);
			transLayer.add(rsv1);
			DefaultMutableTreeNode rsv2=new DefaultMutableTreeNode("rsv2:"+tcpp.rsv2);
			transLayer.add(rsv2);
			DefaultMutableTreeNode window=new DefaultMutableTreeNode("window:"+tcpp.window);
			transLayer.add(window);
			DefaultMutableTreeNode urgent=new DefaultMutableTreeNode("����ָ��:"+tcpp.urgent_pointer);
			transLayer.add(urgent);
		}else if(packet instanceof UDPPacket){
			UDPPacket udpp=(UDPPacket)packet;
			DefaultMutableTreeNode udp=new DefaultMutableTreeNode("Э��:UDP");
			transLayer.add(udp);
			DefaultMutableTreeNode srcPort=new DefaultMutableTreeNode("Դ�˿�:"+udpp.src_port);
			transLayer.add(srcPort);
			DefaultMutableTreeNode dstPort=new DefaultMutableTreeNode("Ŀ�Ķ˿�:"+udpp.dst_port);
			transLayer.add(dstPort);
			DefaultMutableTreeNode len=new DefaultMutableTreeNode("����:"+udpp.len);
			transLayer.add(len);
		}
		root.add(networkLayer);
		root.add(transLayer);
		jtr.setModel(new DefaultTreeModel(root));
	}
	//�����е���Ϣ��ӡ����
	public void printData(int index,JTextArea text){
		Packet packet=v.get(index);
		text.setText("");
		byte[]data=packet.data;
		for(int i=0;i<data.length;i+=16){
			String buf="";
			int j;
			for(j=i;j<i+16&&j<data.length;j++){
				buf+=trans(data[j]);
			}
			text.append(buf+"\r\n");
		}
		String buf="";
		for(int i=0;i<data.length;i+=16){
			for(int j=i;j<i+16&&j<data.length;j++){
				if(data[j]<=127&&data[j]>=0)buf+=(char)data[j];
				else buf+='.';
			}
			//text.append(buf+"\r\n");
		}
		text.append(buf);
	}
	//�Ѻ���pwd��password�İ���ȡ����
	public void stole(DefaultTableModel d,JTable j){
		setJTableModel(d, j);
		v.removeAllElements();
		int num=d.getRowCount();
		for(int i=0;i<num;i++)d.removeRow(0);
		j.setModel(d);
		int cc=0;
		for(int i=0;i<pwd.size();i++){
			String buf=pwd.get(i);
			if(buf.contains("pwd")||buf.contains("password")){
				v.addElement(tot.get(i));
				changeTable(tot.get(i), ++cc, true);
			}
		}
	}
	//��Ԥ����������Ĵ�д��ĸת��Сд��ĸ���Ա����pwd��password
	public void getMessage(){
		for(int i=0;i<tot.size();i++){
			Packet packet=tot.get(i);
			byte[]data=packet.data;
			String buf="";
			for(int j=0;j<data.length;j++){
				if(data[j]<=127&&data[j]>=0){
					if(data[j]>='A'&&data[j]<='Z'){
						buf+=(char)(data[j]+32);
					}else buf+=(char)data[j];
				}
				else buf+='.';
			}
			pwd.add(buf);
		}
	}
	//��byte��ʮ���������
	public String trans(byte s){
		String buf="";
		byte t1,t2;
		t1=(byte)(s&0x0f);//�Ȼ�ȡ����λ
		t2=(byte)((s&0xf0)>>4);//��ȡ����λ
		if(t2>=10){
			buf+=(char) (t2+'A'-10);
		}else buf+=(char)(t2+'0');
		if(t1>=10){
			buf+=(char) (t1+'A'-10);
		}else buf+=(char)(t1+'0');
		buf+="  ";
		return buf;
	}
	//��ץ���İ����й���
	public void filter(String str,DefaultTableModel d,JTable j){
		if(str=="���˹���")return;
		Vector<Packet>tmp=new Vector<Packet>();
		Vector<String>time=new Vector<String>();
		for(int i=0;i<tot.size();i++){
			Packet packet=tot.get(i);
			if(packet instanceof ARPPacket&&str=="ARP")tmp.add(packet);
			if(packet instanceof ICMPPacket&&str=="ICMP")tmp.add(packet);
			if(packet instanceof TCPPacket&&str=="TCP")tmp.add(packet);
			if(packet instanceof UDPPacket&&str=="UDP")tmp.add(packet);
			if(packet instanceof TCPPacket&&str=="HTTP"){
				TCPPacket tcpp=(TCPPacket)packet;
				if(tcpp.src_port==80||tcpp.dst_port==80)tmp.add(packet);
			}
			if(packet instanceof UDPPacket&&str=="HTTP"){
				UDPPacket udpp=(UDPPacket)packet;
				if(udpp.src_port==80||udpp.dst_port==80)tmp.add(packet);
			}
		}
		v=tmp;
		int num=d.getRowCount();
		for(int i=0;i<num;i++)d.removeRow(0);
		setJTableModel(d, j);
		for(int i=0;i<v.size();i++)changeTable(v.get(i),i+1,true);
	}
	//����ͳ�ư��ĸ���
	public void updateCount(JLabel j[]){
		int count[]=new int[5];
		for(int i=0;i<5;i++)count[i]=0;
		for(int i=0;i<tot.size();i++){
			Packet packet=tot.get(i);
			if(packet instanceof ARPPacket)count[3]++;
			if(packet instanceof ICMPPacket)count[2]++;
			if(packet instanceof TCPPacket)count[0]++;
			if(packet instanceof UDPPacket)count[1]++;
			if(packet instanceof TCPPacket){
				TCPPacket tcpp=(TCPPacket)packet;
				if(tcpp.src_port==80||tcpp.dst_port==80)count[4]++;
			}
			if(packet instanceof UDPPacket){
				UDPPacket udpp=(UDPPacket)packet;
				if(udpp.src_port==80||udpp.dst_port==80)count[4]++;
			}
		}
		for(int i=0;i<5;i++)j[i].setText(Integer.toString(count[i]));
	}
	//����ʼ��ťʱ��������������ʼ��
	public void initial(DefaultTableModel d,JTable j,JLabel jl[]){
		v.removeAllElements();
		tot.removeAllElements();
		pwd.removeAllElements();
		int num=d.getRowCount();
		for(int i=0;i<5;i++){
			jl[i].setText("0");
		}
		for(int i=0;i<num;i++)d.removeRow(0);
		j.setModel(d);
	}
	//��ȡ�õ���������Ϣ���Ը��������б�
	public String[]getNetworkCard(){
		return buf;
	}
	//�����߳����б�־
	public void setRunning(boolean s){
		running=s;
	}
	//���ڸ���JTable
	public void setJTableModel(DefaultTableModel d,JTable j){
		model=d;
		jt=j;
	}
}
	