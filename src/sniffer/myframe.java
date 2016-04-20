package sniffer;

import java.awt.BorderLayout;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.rmi.activation.ActivationInstantiator;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.event.TreeModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import jdk.internal.org.objectweb.asm.tree.analysis.Analyzer;
import sniffer.mysniffer;

public class myframe extends JFrame implements ActionListener{
	JFrame jf;
	JButton start,stop,filter,stole;//几个按钮
	JComboBox<String> jc1,jc2;//下拉列表，用于选择网卡和过滤规则
	String[] columnNames={"no.","time","source","destination","protocol","length"};
	Object[][] data=new Object[0][6];
	JTable jt;//用于显示抓到的包的表格
	DefaultTableModel dt;
	
	DefaultMutableTreeNode root=new DefaultMutableTreeNode("包分析");
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	JTree tree=new JTree(treeModel);//使用树状组件展示包头中各字段的内容
	
	JScrollPane jsp,jsp1,jsp2;
	mysniffer snif;
	JTextArea jta;//用于显示包的内容
	JLabel j[],count[];//用于显示统计结果
	JLabel tt;
	public myframe(){
		count=new JLabel[5];
		j=new JLabel[5];
		for(int i=0;i<5;i++){
			count[i]=new JLabel();
			j[i]=new JLabel();
			count[i].setFont(new Font("楷体", Font.PLAIN, 20));
			j[i].setFont(new Font("楷体", Font.PLAIN, 15));
			count[i].setText("0");
		}
		j[0].setText("TCP");
		j[1].setText("UDP");
		j[2].setText("ICMP");
		j[3].setText("ARP");
		j[4].setText("HTTP");
		snif=new mysniffer();
		jf=new JFrame("sniffer");
		jf.setLayout(null);
		start=new JButton("开始");
		stop=new JButton("停止");
		filter=new JButton("过滤");
		stole=new JButton("密码嗅探");
		jc1=new JComboBox<String>();
		String str[]={"过滤规则","TCP","UDP","ICMP","ARP","HTTP"};
		jc2=new JComboBox<String>(str);
		jt=new JTable();
		dt=new DefaultTableModel(data, columnNames);
		jt.setModel(dt);
		jt.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		jsp=new JScrollPane(jt);
		jsp1=new JScrollPane(tree);
		jta=new JTextArea();
		jsp2=new JScrollPane(jta);
		jf.setSize(1000, 700);
		//将各种组件加入到窗体中
		jf.add(jc1);
		jf.add(start);
		jf.add(stop);
		jf.add(filter);
		jf.add(stole);
		jf.add(jc2);
		jf.add(jsp);
		jf.add(jsp1);
		jf.add(jsp2);
		for(int i=0;i<5;i++){
			jf.add(count[i]);
			jf.add(j[i]);
		}
		//设置各种组件的大小位置
		jta.setBounds(300, 300, 500, 300);
		jsp2.setBounds(300, 300, 500, 300);
		tree.setBounds(25, 300, 250, 300);
		jsp1.setBounds(25, 300, 250, 300);
		jsp.setBounds(25, 80, 940, 200);
		jc1.setBounds(5, 5, 400, 20);
		int off=80;
		for(int i=0;i<5;i++){
			j[i].setBounds(830,190+off,40,80);
			count[i].setBounds(880, 190+off, 80, 80);
			off+=80;
		}
		jc2.setBounds(5, 35, 400, 20);
		start.setBounds(500, 10, 80,35);
		stop.setBounds(600,10,80,35);
		filter.setBounds(700,10,80,35);
		stole.setBounds(800,10,150,35);
		//各个组件功能设置
		jta.setLineWrap(false);
		jc1.addItem("选择网卡");
		setCombobox(snif.getNetworkCard(), jc1);
		jt.addMouseListener(new MouseAdapter() {//对表格绑定点击事件
			public void mouseClicked(MouseEvent e){
				if(e.getClickCount()==1){
					int index=((JTable)e.getSource()).rowAtPoint(e.getPoint());
					snif.analyze(index,tree);//对包头进行分析
					snif.printData(index,jta);//将包的内容输出到文本框中
				}
			}
		});
		//几个按钮绑定点击事件
		start.addActionListener(this);	
		stop.addActionListener(this);
		filter.addActionListener(this);
		stole.addActionListener(this);
		jf.setVisible(true);
	}
	private void setCombobox(String buf[],JComboBox<String> jc){
		for(int i=0;i<buf.length;i++){
			jc.insertItemAt(buf[i], i+1);
		}
	}
	public void actionPerformed(ActionEvent e){
		if(e.getSource()==start){
			snif.setRunning(true);//设置线程运行标志
			if(jc1.getSelectedIndex()==0){//获取网卡序号
				JOptionPane.showMessageDialog(null, "请选择网卡", "alert", JOptionPane.ERROR_MESSAGE); 
				return;
			}
			snif.setJTableModel(dt, jt);//将JTable控件传进去，在每抓到一个包时将其添加到JTable中去显示
			snif.initial(dt, jt,count);//点击开始，要将之前的结果都清空掉
			if(snif.work(jc1.getSelectedIndex())<0){//调用mysniffer中的work函数进行抓包
				JOptionPane.showMessageDialog(null, "打开设备失败", "alert", JOptionPane.ERROR_MESSAGE); 
				return;
			}
		}else if(e.getSource()==stop){
			snif.setRunning(false);//设置线程停止的标志
			snif.updateCount(count);//对包的个数的统计
		}else if(e.getSource()==filter){
			snif.filter((String)jc2.getSelectedItem(),dt,jt);//对抓到的包进行过滤
		}else if(e.getSource()==stole){
			snif.getMessage();//将数据包内容中所有的大写字母转成小写字母
			snif.stole(dt, jt);//将数据包中含有pwd或是password字段的包提取出来
		}
	}
}
