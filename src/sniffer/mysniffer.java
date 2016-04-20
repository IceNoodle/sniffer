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
	private Vector<Packet>v,tot;//tot记录该次抓包后总的结果，v记录当前显示在页面的结果
	private Vector<String>pwd;
	private DefaultTableModel model;
	private JTable jt=null;
	//构造函数，初始化各个变量
	public mysniffer(){
		running=false;
		v=new Vector<Packet>();
		tot=new Vector<Packet>();
		pwd=new Vector<String>();
		devices= JpcapCaptor.getDeviceList(); 
		buf=new String[devices.length];
		for(int i=0;i<devices.length;i++)buf[i]=devices[i].name;
	}
	//进行抓包
	public int work(int index){
		try {
			//第三个变量为设置网卡为混杂模式
			jpcap=JpcapCaptor.openDevice(devices[index-1], 65536, true, 100);
			capThread(jpcap);
		} catch (IOException e) {
			return -1;
		}
		return 1;
	}
	//建立抓包的线程
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
	//对抓到的包进行处理
	class testPacketReceiver implements PacketReceiver{
		public void receivePacket(Packet packet){
			if(judge(packet)>=0){
				v.add(packet);//将抓到的包添加到v，tot两个vector<packet>中去，以待进一步处理
				tot.add(packet);
				changeTable(packet,0,false);//添加到Jtable表格中去
			}
		}
	}
	//将抓到的包添加到JTabel中去
	private void changeTable(Packet packet,int index,boolean useIndex){
		Object data[]=new Object[6];
		if(!useIndex)data[0]=String.valueOf(v.size());//将编号赋值
		else data[0]=String.valueOf(index);
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");//设置日期格式
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
	//判别是什么包
	private int judge(Packet packet){	
		if(packet instanceof jpcap.packet.TCPPacket)return 1;
		else if(packet instanceof jpcap.packet.UDPPacket)return 2;
		else if(packet instanceof jpcap.packet.ARPPacket)return 3;
		else if(packet instanceof jpcap.packet.ICMPPacket)return 4;
		return 0;
	}
	//对包头的信息添加到JTree中去
	public void analyze(int index,JTree jtr){
		Packet packet=v.get(index);
		DefaultMutableTreeNode root=new DefaultMutableTreeNode("数据包分析");
		DatalinkPacket data=packet.datalink;
		if(data instanceof EthernetPacket){
			EthernetPacket ep=(EthernetPacket)data;
			DefaultMutableTreeNode linkLayer=new DefaultMutableTreeNode("数据链路层");
			linkLayer.add(new DefaultMutableTreeNode("源MAC:"+ep.getSourceAddress()));
			linkLayer.add(new DefaultMutableTreeNode("目的MAC:"+ep.getDestinationAddress()));
			root.add(linkLayer);
		}
		DefaultMutableTreeNode networkLayer=new DefaultMutableTreeNode("网络层");
		if(packet instanceof IPPacket){
			IPPacket ipp=(IPPacket)packet;
			DefaultMutableTreeNode version=new DefaultMutableTreeNode("版本号:IPV"+ipp.version);
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
				DefaultMutableTreeNode offset=new DefaultMutableTreeNode("段偏移:"+ipp.offset);
				networkLayer.add(offset);
				DefaultMutableTreeNode id=new DefaultMutableTreeNode("标识:"+ipp.ident);
				networkLayer.add(id);
				DefaultMutableTreeNode ttl=new DefaultMutableTreeNode("生存期:"+ipp.hop_limit);
				networkLayer.add(ttl);
				DefaultMutableTreeNode proto=new DefaultMutableTreeNode("协议:"+ipp.protocol);
				networkLayer.add(proto);
				DefaultMutableTreeNode srcIp=new DefaultMutableTreeNode("源IP:"+ipp.src_ip);
				networkLayer.add(srcIp);
				DefaultMutableTreeNode dstIp=new DefaultMutableTreeNode("目的IP:"+ipp.dst_ip);
				networkLayer.add(dstIp);
			}else{
				DefaultMutableTreeNode cls=new DefaultMutableTreeNode("流类型:"+ipp.priority);
				networkLayer.add(cls);
				DefaultMutableTreeNode flowLabel=new DefaultMutableTreeNode("流标签:"+ipp.flow_label);
				networkLayer.add(flowLabel);
				DefaultMutableTreeNode nextHdr=new DefaultMutableTreeNode("下一个首部:"+ipp.protocol);
				networkLayer.add(nextHdr);
				DefaultMutableTreeNode ttl=new DefaultMutableTreeNode("生存期:"+ipp.hop_limit);
				networkLayer.add(ttl);
				DefaultMutableTreeNode srcIp=new DefaultMutableTreeNode("源IP:"+ipp.src_ip);
				networkLayer.add(srcIp);
				DefaultMutableTreeNode dstIp=new DefaultMutableTreeNode("目的IP:"+ipp.dst_ip);
				networkLayer.add(dstIp);
			}
		}else if(packet instanceof ARPPacket){
			ARPPacket arpp=(ARPPacket)packet;
			DefaultMutableTreeNode arp=new DefaultMutableTreeNode("协议:ARP");
			networkLayer.add(arp);
			DefaultMutableTreeNode hardType=new DefaultMutableTreeNode("硬件类型:"+arpp.hardtype);
			networkLayer.add(hardType);
			DefaultMutableTreeNode proto=new DefaultMutableTreeNode("协议类型:"+arpp.prototype);
			networkLayer.add(proto);
			DefaultMutableTreeNode hLen=new DefaultMutableTreeNode("硬件地址长度:"+arpp.hlen);
			networkLayer.add(hLen);
			DefaultMutableTreeNode pLen=new DefaultMutableTreeNode("协议地址长度:"+arpp.plen);
			networkLayer.add(pLen);
			DefaultMutableTreeNode op=new DefaultMutableTreeNode("操作码:"+arpp.operation);
			networkLayer.add(op);
			DefaultMutableTreeNode macSrc=new DefaultMutableTreeNode("源MAC:"+arpp.getSenderHardwareAddress());
			networkLayer.add(macSrc);
			DefaultMutableTreeNode ipSrc=new DefaultMutableTreeNode("源IP:"+arpp.getSenderProtocolAddress());
			networkLayer.add(ipSrc);
			DefaultMutableTreeNode macDst=new DefaultMutableTreeNode("目的MAC:"+arpp.getTargetHardwareAddress());
			networkLayer.add(macDst);
			DefaultMutableTreeNode ipDst=new DefaultMutableTreeNode("目的IP:"+arpp.getTargetProtocolAddress());
			networkLayer.add(ipDst);
		}else if(packet instanceof ICMPPacket){
			ICMPPacket icmpp=(ICMPPacket)packet;
			DefaultMutableTreeNode icmp=new DefaultMutableTreeNode("协议:ICMP");
			networkLayer.add(icmp);
			DefaultMutableTreeNode type=new DefaultMutableTreeNode("类型:"+icmpp.type);
			networkLayer.add(type);
			DefaultMutableTreeNode code=new DefaultMutableTreeNode("代码:"+icmpp.code);
			networkLayer.add(code);
			DefaultMutableTreeNode check=new DefaultMutableTreeNode("校验和:"+icmpp.checksum);
			networkLayer.add(check);
			DefaultMutableTreeNode id=new DefaultMutableTreeNode("标识:"+icmpp.id);
			networkLayer.add(id);
			DefaultMutableTreeNode seq=new DefaultMutableTreeNode("序列号:"+icmpp.seq);
			networkLayer.add(seq);
		}
		DefaultMutableTreeNode transLayer=new DefaultMutableTreeNode("传输层");
		if(packet instanceof TCPPacket){
			TCPPacket tcpp=(TCPPacket)packet;
			DefaultMutableTreeNode tcp=new DefaultMutableTreeNode("协议:TCP");
			transLayer.add(tcp);
			DefaultMutableTreeNode srcPort=new DefaultMutableTreeNode("源端口:"+tcpp.src_port);
			transLayer.add(srcPort);
			DefaultMutableTreeNode dstPort=new DefaultMutableTreeNode("目的端口:"+tcpp.dst_port);
			transLayer.add(dstPort);
			DefaultMutableTreeNode seq=new DefaultMutableTreeNode("序列号:"+tcpp.sequence);
			transLayer.add(seq);
			DefaultMutableTreeNode check=new DefaultMutableTreeNode("校验和:"+tcpp.ack_num);
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
			DefaultMutableTreeNode urgent=new DefaultMutableTreeNode("紧急指针:"+tcpp.urgent_pointer);
			transLayer.add(urgent);
		}else if(packet instanceof UDPPacket){
			UDPPacket udpp=(UDPPacket)packet;
			DefaultMutableTreeNode udp=new DefaultMutableTreeNode("协议:UDP");
			transLayer.add(udp);
			DefaultMutableTreeNode srcPort=new DefaultMutableTreeNode("源端口:"+udpp.src_port);
			transLayer.add(srcPort);
			DefaultMutableTreeNode dstPort=new DefaultMutableTreeNode("目的端口:"+udpp.dst_port);
			transLayer.add(dstPort);
			DefaultMutableTreeNode len=new DefaultMutableTreeNode("长度:"+udpp.len);
			transLayer.add(len);
		}
		root.add(networkLayer);
		root.add(transLayer);
		jtr.setModel(new DefaultTreeModel(root));
	}
	//将包中的信息打印出来
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
	//把含有pwd，password的包提取出来
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
	//作预处理，将包里的大写字母转成小写字母，以便查找pwd，password
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
	//将byte以十六进制输出
	public String trans(byte s){
		String buf="";
		byte t1,t2;
		t1=(byte)(s&0x0f);//先获取低四位
		t2=(byte)((s&0xf0)>>4);//获取高四位
		if(t2>=10){
			buf+=(char) (t2+'A'-10);
		}else buf+=(char)(t2+'0');
		if(t1>=10){
			buf+=(char) (t1+'A'-10);
		}else buf+=(char)(t1+'0');
		buf+="  ";
		return buf;
	}
	//对抓到的包进行过滤
	public void filter(String str,DefaultTableModel d,JTable j){
		if(str=="过滤规则")return;
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
	//用来统计包的个数
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
	//按开始按钮时，将各个变量初始化
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
	//获取得到的网卡信息，以更新下拉列表
	public String[]getNetworkCard(){
		return buf;
	}
	//设置线程运行标志
	public void setRunning(boolean s){
		running=s;
	}
	//用于更新JTable
	public void setJTableModel(DefaultTableModel d,JTable j){
		model=d;
		jt=j;
	}
}
	